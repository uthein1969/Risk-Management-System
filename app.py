"""
Risk Management Web Application
- STR (Suspicious Transaction Report)
- TTR (Threshold Transaction Report)
- Merchant KYC Inspection
- Blacklist Check
"""

import os
import csv
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'risk-management-secret-key-2026'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'data')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'csv'}

# ─── In-memory data store ───
data_store = {
    'transactions': [],     # list of dicts
    'merchants': [],
    'blacklist': [],
    'last_upload': None,
    'file_names': {}
}

# ─── STR/TTR Configuration ───
CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'data', 'risk_config.json')

DEFAULT_CONFIG = {
    'str': {
        'large_transaction': 50000,      # Single txn >= this = MEDIUM
        'structuring_threshold': 10000,  # Small txn under this
        'structuring_count': 3,          # >= this many small txns in 24h
        'structuring_total': 10000,      # Total of small txns exceeds this
        'round_amount_min': 5000,        # Round amount >= this
        'high_freq_count': 5,            # > this many txns in 1 hour
        'high_freq_hours': 1,            # Time window in hours
    },
    'ttr': {
        'threshold': 10000,              # Flag txns >= this amount
    },
    'kyc': {
        'high_risk_types': ['money exchange', 'casino', 'crypto', 'pawnshop', 'night club', 'arms dealer'],
        'new_merchant_days': 30,         # Merchant newer than this = MEDIUM
    },
    'columns': {
        # STR report visible columns (field_name: label)
        'str': {
            'transaction_id': 'Transaction ID',
            'account_id': 'Account / Merchant No',
            'amount': 'Amount',
            'transaction_date': 'Date',
            'transaction_type': 'Type',
            'merchant_name': 'Merchant Name',
            'counterparty': 'Debitor Name',
            'phone': 'Phone',
            'status': 'Status',
            'mcc_code': 'MCC Code',
            'customer_party': 'Customer Party',
            'merchant_party': 'Merchant Party',
            'debitor_account': 'Debitor Account',
        },
        # TTR report visible columns
        'ttr': {
            'transaction_id': 'Transaction ID',
            'account_id': 'Account / Merchant No',
            'amount': 'Amount',
            'transaction_date': 'Date',
            'transaction_type': 'Type',
            'merchant_name': 'Merchant Name',
            'counterparty': 'Debitor Name',
            'phone': 'Phone',
            'status': 'Status',
            'receiver_amount': 'Receiver Amount',
        },
        # All available columns for selection (populated dynamically)
        'available': {}
    }
}

def load_config():
    """Load config from file, fallback to defaults."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                saved = json.load(f)
            # Merge with defaults (in case new fields added)
            config = DEFAULT_CONFIG.copy()
            for section in ['str', 'ttr', 'kyc']:
                if section in saved:
                    config[section] = {**DEFAULT_CONFIG[section], **saved[section]}
            return config
    except Exception:
        pass
    return DEFAULT_CONFIG.copy()

def save_config(config):
    """Save config to file."""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def load_csv(filepath):
    """Load CSV file into list of dicts."""
    rows = []
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cleaned = {k.strip(): v.strip() if v else '' for k, v in row.items()}
                rows.append(cleaned)
    except Exception as e:
        flash(f'CSV read error: {str(e)}', 'error')
    return rows


def load_excel(filepath):
    """Load Excel file using openpyxl directly."""
    try:
        import openpyxl
        wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
        ws = wb.active
        rows = []
        headers = []
        for i, row in enumerate(ws.iter_rows(values_only=True)):
            if i == 0:
                headers = [str(c).strip() if c else f'col_{j}' for j, c in enumerate(row)]
            else:
                row_dict = {}
                for j, val in enumerate(row):
                    if j < len(headers):
                        row_dict[headers[j]] = str(val).strip() if val is not None else ''
                rows.append(row_dict)
        wb.close()
        return rows
    except Exception as e:
        flash(f'Excel read error: {str(e)}', 'error')
        return []


# ─── MMQR Column Mapping ───
MMQR_COLUMN_MAP = {
    'Transaction Date': 'transaction_date',
    'Transaction ID': 'transaction_id',
    'Transaction Amount': 'amount',
    'Transaction Type': 'transaction_type',
    'Merchant No': 'account_id',
    'Debitor Name': 'counterparty',
    'Debitor Account': 'debitor_account',
    'Merchant Name': 'merchant_name',
    'Merchant Type': 'merchant_type',
    'MCC Codes': 'mcc_code',
    'Phone No': 'phone',
    'Customer Party': 'customer_party',
    'Merchant Party': 'merchant_party',
    'Creditor Name': 'creditor_name',
    'Status': 'status',
    'Receiver Amount': 'receiver_amount',
    'MDR': 'mdr',
    'DPS Fees': 'dps_fees',
    'Income': 'income',
    'Original Transaction ID': 'original_transaction_id',
    'Refund reason': 'refund_reason',
}


def is_mmqr_format(rows):
    """Detect if data is MMQR format."""
    if not rows:
        return False
    return 'Transaction Date' in rows[0] and 'Transaction Amount' in rows[0]


def map_mmqr_rows(rows):
    """Map MMQR column names to internal field names."""
    mapped = []
    for row in rows:
        new_row = {}
        for mmqr_col, internal_col in MMQR_COLUMN_MAP.items():
            new_row[internal_col] = row.get(mmqr_col, '')
        # Keep original columns too for display
        for k, v in row.items():
            if k not in MMQR_COLUMN_MAP:
                new_row[k] = v
        mapped.append(new_row)
    return mapped


def load_file(filepath):
    """Auto-detect and load CSV or Excel."""
    ext = filepath.rsplit('.', 1)[1].lower() if '.' in filepath else ''
    if ext == 'csv':
        rows = load_csv(filepath)
    elif ext in ('xlsx', 'xls'):
        rows = load_excel(filepath)
    else:
        return []
    # Auto-detect MMQR format and map columns
    if rows and is_mmqr_format(rows):
        return map_mmqr_rows(rows)
    return rows


def safe_float(val, default=0):
    try:
        return float(str(val).replace(',', ''))
    except:
        return default


def safe_date(val):
    try:
        return datetime.strptime(str(val)[:19], '%Y-%m-%d %H:%M:%S')
    except:
        try:
            return datetime.strptime(str(val)[:10], '%Y-%m-%d')
        except:
            return None


# ─── STR Detection Rules ───
def detect_str(data, config=None):
    if not data:
        return []

    if config is None:
        config = load_config()
    cfg = config['str']

    results = []
    threshold = cfg['structuring_threshold']
    large_threshold = cfg['large_transaction']
    round_min = cfg['round_amount_min']
    str_count = cfg['structuring_count']
    str_total = cfg['structuring_total']
    freq_count = cfg['high_freq_count']
    freq_hours = cfg['high_freq_hours']

    # Group by account
    by_account = {}
    for row in data:
        acct = row.get('account_id', '')
        if acct:
            by_account.setdefault(acct, []).append(row)

    for row in data:
        txn_id = row.get('transaction_id', '')
        acct = row.get('account_id', '')
        amount = safe_float(row.get('amount', 0))

        if not txn_id or not acct:
            continue

        # Rule 1: Large Transaction
        if amount >= large_threshold:
            r = dict(row)
            r.update({'rule': 'Large Transaction', 'severity': 'MEDIUM', 'amount': amount, 'date': str(row.get('transaction_date', ''))[:19], 'details': f'Single txn {amount:,.0f} >= {large_threshold:,}'})
            results.append(r)

        # Rule 2: Round Amount
        if amount > 0 and amount % 1000 == 0 and amount >= round_min:
            r = dict(row)
            r.update({'rule': 'Round Amount', 'severity': 'LOW', 'amount': amount, 'date': str(row.get('transaction_date', ''))[:19], 'details': f'Round amount: {amount:,.0f} >= {round_min:,}'})
            results.append(r)

    # Rule 3: Structuring
    for acct, txns in by_account.items():
        dated = [(t, safe_date(t.get('transaction_date'))) for t in txns]
        dated = [(t, d) for t, d in dated if d]
        dated.sort(key=lambda x: x[1])

        for i, (txn, dt) in enumerate(dated):
            window = [t for t, d in dated if d >= dt - timedelta(hours=24) and d <= dt]
            small = [t for t in window if 0 < safe_float(t.get('amount', 0)) < threshold]
            total = sum(safe_float(t.get('amount', 0)) for t in small)
            if len(small) >= str_count and total > str_total:
                r = dict(txn)
                r.update({'rule': 'Structuring', 'severity': 'HIGH', 'amount': safe_float(txn.get('amount', 0)), 'date': str(txn.get('transaction_date', ''))[:19], 'details': f'{len(small)} txns totaling {total:,.0f} in 24h (threshold {threshold:,})'})
                results.append(r)

    # Rule 4: High Frequency
    for acct, txns in by_account.items():
        dated = [(t, safe_date(t.get('transaction_date'))) for t in txns]
        dated = [(t, d) for t, d in dated if d]
        dated.sort(key=lambda x: x[1])

        for i, (txn, dt) in enumerate(dated):
            count = sum(1 for _, d in dated if d >= dt - timedelta(hours=freq_hours) and d <= dt)
            if count > freq_count:
                r = dict(txn)
                r.update({'rule': 'High Frequency', 'severity': 'HIGH', 'amount': safe_float(txn.get('amount', 0)), 'date': str(txn.get('transaction_date', ''))[:19], 'details': f'{count} txns in {freq_hours}h (limit {freq_count})'})
                results.append(r)

    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        key = (r['transaction_id'], r['rule'])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


# ─── TTR Detection ───
def detect_ttr(data, threshold=None, config=None):
    if not data:
        return []
    if threshold is None:
        if config is None:
            config = load_config()
        threshold = config['ttr']['threshold']
    results = []
    for row in data:
        amount = safe_float(row.get('amount', 0))
        if amount >= threshold:
            results.append({
                **row,
                'amount': amount,
                'threshold': threshold,
                'status': 'Pending Review'
            })
    return results


# ─── KYC Inspection ───
def inspect_kyc(data):
    if not data:
        return []

    high_risk_types = ['money exchange', 'casino', 'crypto', 'pawnshop', 'night club', 'arms dealer']
    required_fields = ['merchant_id', 'merchant_name', 'business_type', 'registration_date',
                       'owner_name', 'address', 'license_number', 'license_expiry']
    results = []

    for row in data:
        issues = []
        risk_level = 'LOW'

        # Missing fields
        for field in required_fields:
            val = row.get(field, '')
            if not val or val.strip() == '':
                issues.append(f'Missing: {field}')

        # Expired license
        expiry_str = row.get('license_expiry', '')
        if expiry_str:
            exp_date = safe_date(expiry_str)
            if exp_date and exp_date < datetime.now():
                issues.append(f'License expired: {exp_date.strftime("%Y-%m-%d")}')
                risk_level = 'HIGH'

        # High-risk business
        btype = row.get('business_type', '').lower()
        if any(hr in btype for hr in high_risk_types):
            issues.append(f'High-risk business: {row.get("business_type", "")}')
            risk_level = 'HIGH'

        # New merchant
        reg_str = row.get('registration_date', '')
        if reg_str:
            reg_date = safe_date(reg_str)
            if reg_date:
                age = (datetime.now() - reg_date).days
                if age < 30:
                    issues.append(f'New merchant ({age} days)')
                    if risk_level == 'LOW':
                        risk_level = 'MEDIUM'

        if issues:
            results.append({
                'merchant_id': row.get('merchant_id', 'N/A'),
                'merchant_name': row.get('merchant_name', 'N/A'),
                'business_type': row.get('business_type', 'N/A'),
                'risk_level': risk_level,
                'issue_count': len(issues),
                'issues': '; '.join(issues),
                'status': 'Pending Review'
            })

    return results


# ─── Blacklist Check ───
def check_blacklist(transactions, merchants, blacklist):
    if not blacklist:
        return []

    results = []
    bl_accounts = set(r.get('account_id', '') for r in blacklist if r.get('account_id'))
    bl_merchants = set(r.get('merchant_id', '') for r in blacklist if r.get('merchant_id'))
    bl_names = set(r.get('name', '').lower() for r in blacklist if r.get('name'))
    bl_phones = set(r.get('phone', '') for r in blacklist if r.get('phone'))
    bl_nrc = set(r.get('nrc', '') for r in blacklist if r.get('nrc'))

    for row in transactions:
        matched = []
        acct = row.get('account_id', '')
        if acct in bl_accounts:
            matched.append(f'account_id: {acct}')
        # Also check MMQR fields
        debitor = row.get('counterparty', '').lower()
        if debitor and debitor in bl_names:
            matched.append(f'debitor_name: {row.get("counterparty", "")}')
        phone = row.get('phone', '')
        if phone and phone in bl_phones:
            matched.append(f'phone: {phone}')
        merchant_name = row.get('merchant_name', '').lower()
        if merchant_name and merchant_name in bl_names:
            matched.append(f'merchant_name: {row.get("merchant_name", "")}')
        if matched:
            results.append({
                'source': 'Transaction',
                'id': row.get('transaction_id', 'N/A'),
                'name': row.get('counterparty', '') or acct or row.get('merchant_name', 'N/A'),
                'amount': safe_float(row.get('amount', 0)),
                'matched_on': '; '.join(matched),
                'severity': 'CRITICAL',
                'status': 'Flagged'
            })

    for row in merchants:
        matched = []
        mid = row.get('merchant_id', '')
        if mid in bl_merchants:
            matched.append(f'merchant_id: {mid}')
        owner = row.get('owner_name', '').lower()
        if owner in bl_names:
            matched.append(f'owner_name: {row.get("owner_name", "")}')
        phone = row.get('phone', '')
        if phone in bl_phones:
            matched.append(f'phone: {phone}')
        nrc = row.get('nrc', '')
        if nrc in bl_nrc:
            matched.append(f'nrc: {nrc}')
        if matched:
            results.append({
                'source': 'Merchant',
                'id': mid,
                'name': row.get('merchant_name', 'N/A'),
                'amount': '-',
                'matched_on': '; '.join(matched),
                'severity': 'CRITICAL',
                'status': 'Flagged'
            })

    return results


# ─── Routes ───
@app.route('/')
def dashboard():
    config = load_config()
    str_results = detect_str(data_store['transactions'], config)
    ttr_results = detect_ttr(data_store['transactions'], config=config)
    kyc_results = inspect_kyc(data_store['merchants'])
    bl_results = check_blacklist(data_store['transactions'], data_store['merchants'], data_store['blacklist'])

    stats = {
        'total_transactions': len(data_store['transactions']),
        'total_merchants': len(data_store['merchants']),
        'total_blacklist': len(data_store['blacklist']),
        'str_count': len(str_results),
        'ttr_count': len(ttr_results),
        'kyc_issues': len(kyc_results),
        'blacklist_hits': len(bl_results),
        'last_upload': data_store['last_upload']
    }
    return render_template('dashboard.html', stats=stats)


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        for field, key in [('transactions_file', 'transactions'), ('merchants_file', 'merchants'), ('blacklist_file', 'blacklist')]:
            f = request.files.get(field)
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                f.save(filepath)
                data_store[key] = load_file(filepath)
                data_store['file_names'][key] = filename
                data_store['last_upload'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                flash(f'{key.title()} loaded: {len(data_store[key])} rows', 'success')
                if data_store[key] and 'transaction_id' in data_store[key][0] and 'Transaction Date' not in data_store[key][0]:
                    flash('MMQR format detected - columns auto-mapped', 'info')
        return redirect(url_for('upload'))
    return render_template('upload.html', file_names=data_store['file_names'])


@app.route('/str')
def str_report():
    config = load_config()
    results = detect_str(data_store['transactions'], config)
    summary = {}
    if results:
        sevs = [r['severity'] for r in results]
        rules = [r['rule'] for r in results]
        summary = {
            'total': len(results),
            'high': sevs.count('HIGH'),
            'medium': sevs.count('MEDIUM'),
            'low': sevs.count('LOW'),
            'by_rule': {r: rules.count(r) for r in set(rules)}
        }
    # Get available columns from uploaded data
    available = {}
    if data_store['transactions']:
        available = {k: k.replace('_', ' ').title() for k in data_store['transactions'][0].keys()}
    visible_cols = config.get('columns', {}).get('str', DEFAULT_CONFIG['columns']['str'])
    return render_template('str_report.html', results=results, summary=summary, visible_cols=visible_cols, available_cols=available)


@app.route('/ttr')
def ttr_report():
    config = load_config()
    threshold = request.args.get('threshold', None, type=float)
    if threshold is None:
        threshold = config['ttr']['threshold']
    results = detect_ttr(data_store['transactions'], threshold, config=config)
    summary = {}
    if results:
        amounts = [r['amount'] for r in results]
        types = [r.get('transaction_type', '') for r in results]
        summary = {
            'total': len(results),
            'total_amount': sum(amounts),
            'avg_amount': sum(amounts) / len(amounts),
            'by_type': {t: types.count(t) for t in set(types) if t}
        }
    # Get available columns from uploaded data
    available = {}
    if data_store['transactions']:
        available = {k: k.replace('_', ' ').title() for k in data_store['transactions'][0].keys()}
    visible_cols = config.get('columns', {}).get('ttr', DEFAULT_CONFIG['columns']['ttr'])
    return render_template('ttr_report.html', results=results, summary=summary, threshold=threshold, visible_cols=visible_cols, available_cols=available)


@app.route('/kyc')
def kyc_inspection():
    results = inspect_kyc(data_store['merchants'])
    summary = {}
    if results:
        levels = [r['risk_level'] for r in results]
        summary = {
            'total': len(results),
            'high': levels.count('HIGH'),
            'medium': levels.count('MEDIUM'),
            'low': levels.count('LOW'),
        }
    return render_template('kyc_inspection.html', results=results, summary=summary)


@app.route('/blacklist')
def blacklist_check():
    results = check_blacklist(data_store['transactions'], data_store['merchants'], data_store['blacklist'])
    sources = [r['source'] for r in results]
    summary = {
        'total_hits': len(results),
        'txn_hits': sources.count('Transaction'),
        'merchant_hits': sources.count('Merchant'),
    }
    return render_template('blacklist.html', results=results, summary=summary)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    config = load_config()
    if request.method == 'POST':
        # Update STR config
        config['str']['large_transaction'] = int(request.form.get('str_large_transaction', 50000))
        config['str']['structuring_threshold'] = int(request.form.get('str_structuring_threshold', 10000))
        config['str']['structuring_count'] = int(request.form.get('str_structuring_count', 3))
        config['str']['structuring_total'] = int(request.form.get('str_structuring_total', 10000))
        config['str']['round_amount_min'] = int(request.form.get('str_round_amount_min', 5000))
        config['str']['high_freq_count'] = int(request.form.get('str_high_freq_count', 5))
        config['str']['high_freq_hours'] = int(request.form.get('str_high_freq_hours', 1))
        # Update TTR config
        config['ttr']['threshold'] = int(request.form.get('ttr_threshold', 10000))
        # Update KYC config
        config['kyc']['new_merchant_days'] = int(request.form.get('kyc_new_merchant_days', 30))
        hrt = request.form.get('kyc_high_risk_types', '')
        config['kyc']['high_risk_types'] = [t.strip().lower() for t in hrt.split(',') if t.strip()]
        # Update column visibility
        if 'columns' not in config:
            config['columns'] = {}
        str_cols = request.form.getlist('str_columns')
        ttr_cols = request.form.getlist('ttr_columns')
        if str_cols:
            labels = {c: c.replace('_', ' ').title() for c in str_cols}
            config['columns']['str'] = labels
        if ttr_cols:
            labels = {c: c.replace('_', ' ').title() for c in ttr_cols}
            config['columns']['ttr'] = labels
        save_config(config)
        flash('Configuration saved successfully!', 'success')
        return redirect(url_for('settings'))
    # Get available columns from uploaded data
    available = {}
    if data_store['transactions']:
        available = {k: k.replace('_', ' ').title() for k in data_store['transactions'][0].keys()}
    return render_template('settings.html', config=config, available_cols=available)


@app.route('/api/stats')
def api_stats():
    str_r = detect_str(data_store['transactions'])
    ttr_r = detect_ttr(data_store['transactions'])
    kyc_r = inspect_kyc(data_store['merchants'])

    str_rules = [r['rule'] for r in str_r]
    ttr_types = [r.get('transaction_type', '') for r in ttr_r]
    kyc_levels = [r['risk_level'] for r in kyc_r]

    return jsonify({
        'str_by_rule': {r: str_rules.count(r) for r in set(str_rules)} if str_rules else {},
        'ttr_by_type': {t: ttr_types.count(t) for t in set(ttr_types) if t} if ttr_types else {},
        'kyc_by_level': {l: kyc_levels.count(l) for l in set(kyc_levels)} if kyc_levels else {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
    })


@app.route('/download-template/<template_type>')
def download_template(template_type):
    templates = {
        'transactions': 'transaction_id,account_id,amount,transaction_date,transaction_type,counterparty,currency\nTXN001,ACC001,5000,2026-08-01 10:30:00,Transfer,ACC005,MMK\n',
        'merchants': 'merchant_id,merchant_name,business_type,registration_date,owner_name,address,license_number,license_expiry,phone,nrc\nMERCH001,ABC Shop,Retail,2025-01-15,U Aung,123 Yangon,MEM-001,2027-06-30,09123456789,12/MAHA(N)123456\n',
        'blacklist': 'account_id,merchant_id,name,phone,nrc,reason,date_added\n,,U Bad Guy,09999999999,12/MAHA(N)99999,Fraud,2026-01-01\n',
        'mmqr': 'Transaction Date,Transaction ID,E2E ID/Refereneces Number,Clearing System Ref,Transaction Type,Customer Party,Merchant Party,Debitor Name,Debitor Account,Merchant Type,MCC Codes,Merchant Name,Phone No,Creditor Name,Merchant No,Transaction Amount,MDR,MDR Ratio RI,MDR Ratio OI,DPS Fees,DPS Expense,Cashback Expense,Income,Receiver Amount,Status,Original Transaction ID,Refund reason code,Refund reason\n2026-08-20 10:00:00,TXN001,E2E001,CLR001,MMQR_PAYMENT,2102 - KBZ OI,4203 - MMIV RI,Daw Aye Aye,2237369900000001,MRCTBANK,5499,MYA SHOP,09123456789,MYA SHOP,2237560000000001,"50,000.00",0.00,0.00,0.00,25.00,0.00,0.00,0.00,"50,000.00",SUCCESS,,,\n'
    }
    if template_type not in templates:
        flash('Template not found', 'error')
        return redirect(url_for('upload'))
    return Response(
        templates[template_type],
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={template_type}_template.csv'}
    )


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=3000)
