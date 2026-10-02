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
    'file_names': {},
    'excel_columns': []     # list of original column names from uploaded Excel/CSV
}

# ─── Exact 28 Columns from Excel File (as in Excel Columns.png) ───
EXCEL_COLUMNS = [
    'Transaction Date',
    'Transaction ID',
    'E2E ID/Refereneces Number',
    'Clearing System Ref',
    'Transaction Type',
    'Customer Party',
    'Merchant Party',
    'Debitor Name',
    'Debitor Account',
    'Merchant Type',
    'MCC Codes',
    'Merchant Name',
    'Phone No',
    'Creditor Name',
    'Merchant No',
    'Transaction Amount',
    'MDR',
    'MDR Ratio RI',
    'MDR Ratio OI',
    'DPS Fees',
    'DPS Expense',
    'Cashback Expense',
    'Income',
    'Receiver Amount',
    'Status',
    'Original Transaction ID',
    'Refund reason code',
    'Refund reason'
]

INTERNAL_KEYS = {
    'amount', 'account_id', 'counterparty', 'transaction_date', 'transaction_id',
    'merchant_name', 'merchant_type', 'mcc_code', 'phone', 'customer_party',
    'merchant_party', 'creditor_name', 'status', 'receiver_amount', 'mdr',
    'dps_fees', 'income', 'original_transaction_id', 'refund_reason',
    'debitor_account', 'rule', 'severity', 'details', 'threshold',
    'registration_date', 'business_type', 'owner_name', 'address',
    'license_number', 'license_expiry', 'nrc', 'reason', 'date_added',
    'hourly_group_id', 'hourly_slot', 'frequency_count', 'group_total_amount',
    'group_merchant', 'group_counterparty'
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
        # STR report visible columns (field_name: label) - exactly from 28 Excel columns
        'str': {
            'Transaction Date': 'Transaction Date',
            'Transaction ID': 'Transaction ID',
            'Transaction Amount': 'Transaction Amount',
            'Debitor Name': 'Debitor Name',
            'Debitor Account': 'Debitor Account',
            'Merchant Name': 'Merchant Name',
            'Customer Party': 'Customer Party',
            'Status': 'Status',
        },
        # TTR report visible columns - exactly from 28 Excel columns
        'ttr': {
            'Transaction Date': 'Transaction Date',
            'Transaction ID': 'Transaction ID',
            'Transaction Amount': 'Transaction Amount',
            'Debitor Name': 'Debitor Name',
            'Merchant Name': 'Merchant Name',
            'Customer Party': 'Customer Party',
            'Receiver Amount': 'Receiver Amount',
            'Status': 'Status',
        },
        # All available columns for selection (strictly the 28 Excel columns)
        'available': {col: col for col in EXCEL_COLUMNS}
    }
}

def load_config():
    """Load config from file, fallback to defaults."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved = json.load(f)
            config = json.loads(json.dumps(DEFAULT_CONFIG))
            for section in ['str', 'ttr', 'kyc']:
                if section in saved and isinstance(saved[section], dict):
                    config[section].update(saved[section])
            if 'columns' in saved and isinstance(saved['columns'], dict):
                for col_sec in ['str', 'ttr', 'available']:
                    if col_sec in saved['columns']:
                        config['columns'][col_sec] = saved['columns'][col_sec]
            return config
    except Exception as e:
        print(f"Config load error: {e}")
    return json.loads(json.dumps(DEFAULT_CONFIG))

def save_config(config):
    """Save config to file."""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def load_csv(filepath):
    """Load CSV file into list of dicts and extract headers."""
    rows = []
    headers = []
    try:
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            headers = [h.strip() for h in (reader.fieldnames or []) if h and h.strip()]
            for row in reader:
                cleaned = {k.strip(): v.strip() if v else '' for k, v in row.items() if k}
                rows.append(cleaned)
    except Exception as e:
        flash(f'CSV read error: {str(e)}', 'error')
    return rows, headers


def select_data_sheet(wb):
    """
    Intelligently select the worksheet containing actual tabular data.
    Avoids metadata/column list sheets (e.g. 'Column' sheet with 1 column of names)
    and prefers sheets with multiple columns and relevant keywords.
    Returns (worksheet, header_row_index).
    """
    best_sheet = None
    best_score = -999999
    best_header_idx = 0

    for name in wb.sheetnames:
        sheet = wb[name]
        sample_rows = list(sheet.iter_rows(values_only=True, max_row=15))
        if not sample_rows:
            continue

        max_cols = 0
        best_row_idx = 0
        for idx, r in enumerate(sample_rows):
            non_empty = sum(1 for c in r if c is not None and str(c).strip() != '')
            if non_empty > max_cols:
                max_cols = non_empty
                best_row_idx = idx

        if max_cols <= 1:
            score = -3000
        else:
            score = max_cols * 30 + len(sample_rows) * 5
            name_lower = name.lower()
            if any(k in name_lower for k in ['transaction', 'mmqr', 'report', 'payment', 'export', 'data']):
                score += 1000
            elif any(k in name_lower for k in ['blacklist', 'merchant']):
                score += 500
            if 'column' in name_lower and max_cols < 8:
                score -= 5000

        if score > best_score:
            best_score = score
            best_sheet = sheet
            best_header_idx = best_row_idx

    return (best_sheet if best_sheet else wb.active), best_header_idx


def load_excel(filepath):
    """Load Excel file using openpyxl directly, returning rows and original headers."""
    try:
        import openpyxl
        wb = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
        ws, header_idx = select_data_sheet(wb)
        rows = []
        headers = []

        all_rows = list(ws.iter_rows(values_only=True))
        if not all_rows:
            wb.close()
            return [], []

        if header_idx < len(all_rows):
            header_row = all_rows[header_idx]
            headers = [
                str(c).strip() if c is not None and str(c).strip() != '' else f'Col_{j+1}'
                for j, c in enumerate(header_row)
            ]
        else:
            header_row = all_rows[0]
            headers = [
                str(c).strip() if c is not None and str(c).strip() != '' else f'Col_{j+1}'
                for j, c in enumerate(header_row)
            ]

        for row in all_rows[header_idx + 1:]:
            if not any(c is not None and str(c).strip() != '' for c in row):
                continue
            row_dict = {}
            for j, val in enumerate(row):
                if j < len(headers):
                    h = headers[j]
                    row_dict[h] = str(val).strip() if val is not None else ''
            rows.append(row_dict)

        wb.close()
        return rows, headers
    except Exception as e:
        flash(f'Excel read error: {str(e)}', 'error')
        return [], []


def normalize_blacklist_rows(rows):
    """Normalize field names in blacklist records so both Excel headers and standard keys work."""
    normalized = []
    for r in rows:
        item = dict(r)
        # Name
        name_val = item.get('name') or item.get('Name') or item.get('Customer Name') or item.get('Debitor Name') or ''
        item['name'] = str(name_val).strip()

        # Phone
        phone_val = item.get('phone') or item.get('PhoneNumber') or item.get('Phone No') or item.get('Phone') or item.get('Mobile') or ''
        item['phone'] = str(phone_val).strip()

        # NRC
        nrc_val = item.get('nrc') or item.get('NRC /Passport No/Company Registration No') or item.get('NRC') or item.get('NRC No') or ''
        item['nrc'] = str(nrc_val).strip()

        # Father Name
        father_val = item.get('father_name') or item.get('Father Name') or item.get("Father's Name") or ''
        item['father_name'] = str(father_val).strip()

        # ID Type
        idtype_val = item.get('id_type') or item.get('IDType') or item.get('ID Type') or ('NRC' if item['nrc'] else 'N/A')
        item['id_type'] = str(idtype_val).strip()

        # Account / Merchant / Reason
        item['account_id'] = str(item.get('account_id') or item.get('Account ID') or item.get('Account No') or '').strip()
        item['merchant_id'] = str(item.get('merchant_id') or item.get('Merchant ID') or '').strip()
        item['reason'] = str(item.get('reason') or item.get('Reason') or 'Blacklist Registry').strip()
        item['date_added'] = str(item.get('date_added') or item.get('Date Added') or item.get('Date') or datetime.now().strftime('%Y-%m-%d')).strip()

        normalized.append(item)
    return normalized


def auto_detect_file_type(rows, headers, filename=""):
    """
    Intelligently determine whether the file is transactions, merchants, or blacklist,
    regardless of which input field the user dropped it in.
    """
    if not rows and not headers:
        return 'transactions'

    all_keys = set(str(h).lower() for h in headers)
    if rows:
        all_keys.update(str(k).lower() for k in rows[0].keys())

    fn_lower = filename.lower()

    # Blacklist indicators
    if 'black' in fn_lower or 'bl' in fn_lower:
        return 'blacklist'
    if any(k in all_keys for k in ['nrc', 'idtype', 'father name', 'nrc /passport no/company registration no', 'reason']):
        return 'blacklist'

    # Merchant indicators
    if any(k in all_keys for k in ['business_type', 'owner_name', 'license_number', 'license_expiry', 'registration_date']):
        return 'merchants'
    if 'merchant' in fn_lower and not any(k in all_keys for k in ['transaction date', 'transaction id', 'amount', 'debitor']):
        return 'merchants'

    # Transactions indicators
    if any(k in all_keys for k in ['transaction date', 'transaction id', 'transaction amount', 'amount', 'debitor name', 'merchant no']):
        return 'transactions'
    if is_mmqr_format(rows):
        return 'transactions'

    return 'transactions'


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
    first = rows[0]
    return ('Transaction Date' in first or 'Transaction ID' in first) and ('Transaction Amount' in first or 'amount' in first)


def map_mmqr_rows(rows):
    """Map MMQR column names to internal field names while preserving all original Excel columns."""
    mapped = []
    for row in rows:
        new_row = dict(row)
        for mmqr_col, internal_col in MMQR_COLUMN_MAP.items():
            if mmqr_col in row and row[mmqr_col] != '':
                new_row[internal_col] = row[mmqr_col]
        # Ensure numerical amount exists on standard keys
        if 'amount' not in new_row or not new_row['amount']:
            if 'Transaction Amount' in row:
                new_row['amount'] = safe_float(row['Transaction Amount'])
        else:
            new_row['amount'] = safe_float(new_row['amount'])
        if 'transaction_date' not in new_row or not new_row['transaction_date']:
            if 'Transaction Date' in row:
                new_row['transaction_date'] = row['Transaction Date']
        if 'account_id' not in new_row or not new_row['account_id']:
            if 'Merchant No' in row:
                new_row['account_id'] = row['Merchant No']
        if 'counterparty' not in new_row or not new_row['counterparty']:
            if 'Debitor Name' in row:
                new_row['counterparty'] = row['Debitor Name']
        if 'merchant_name' not in new_row or not new_row['merchant_name']:
            if 'Merchant Name' in row:
                new_row['merchant_name'] = row['Merchant Name']
        mapped.append(new_row)
    return mapped


def load_file(filepath):
    """Auto-detect and load CSV or Excel. Returns (rows, headers)."""
    ext = filepath.rsplit('.', 1)[1].lower() if '.' in filepath else ''
    if ext == 'csv':
        rows, headers = load_csv(filepath)
    elif ext in ('xlsx', 'xls'):
        rows, headers = load_excel(filepath)
    else:
        return [], []
    # Auto-detect MMQR format and map columns
    if rows and is_mmqr_format(rows):
        rows = map_mmqr_rows(rows)
    return rows, headers


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


@app.context_processor
def inject_template_helpers():
    return {
        'safe_float': safe_float,
        'safe_date': safe_date
    }


app.jinja_env.globals['safe_float'] = safe_float
app.jinja_env.globals['safe_date'] = safe_date


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

    # Rule 5: 1-Hour Counterparty Transfer Frequency (Hourly Window by Counterparty & Merchant)
    hourly_cp_map = {}
    for row in data:
        dt = safe_date(row.get('Transaction Date') or row.get('transaction_date'))
        if not dt:
            continue
        h_start = dt.replace(minute=0, second=0)
        h_end = h_start + timedelta(hours=1)
        slot_label = f"{h_start.strftime('%I:%M %p')} - {h_end.strftime('%I:%M %p')}"
        slot_key = f"{dt.strftime('%Y-%m-%d')} ({slot_label})"
        merch = row.get('Merchant Name') or row.get('Creditor Name') or row.get('merchant_name') or 'Unknown Merchant'
        cp = row.get('Debitor Name') or row.get('Customer Party') or row.get('counterparty') or 'Unknown Counterparty'
        k = (merch, slot_key, cp)
        if k not in hourly_cp_map:
            hourly_cp_map[k] = []
        hourly_cp_map[k].append(row)

    for (merch, slot_key, cp), row_list in hourly_cp_map.items():
        if len(row_list) >= 2:
            cnt = len(row_list)
            tot = sum(safe_float(r.get('Transaction Amount') or r.get('amount', 0)) for r in row_list)
            sev = 'HIGH' if cnt >= 4 or tot >= 100000 else 'MEDIUM'
            group_id = f"grp_{abs(hash((merch, slot_key, cp))) % 100000}"
            for r in row_list:
                res = dict(r)
                res.update({
                    'rule': '1-Hour Counterparty Frequency',
                    'severity': sev,
                    'amount': safe_float(r.get('Transaction Amount') or r.get('amount', 0)),
                    'date': str(r.get('Transaction Date') or r.get('transaction_date', ''))[:19],
                    'details': f'Counterparty "{cp}" made {cnt} transfer payments ({tot:,.0f} MMK) to "{merch}" within 1 hour: {slot_key}',
                    'hourly_group_id': group_id,
                    'frequency_count': cnt,
                    'group_total_amount': tot,
                    'group_merchant': merch,
                    'group_counterparty': cp,
                    'group_slot': slot_key
                })
                results.append(res)

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


# ─── Template Filters & Column Helpers ───
def get_available_columns():
    """Get all unique available columns matching Excel file headers (strictly the 28 columns)."""
    cols = []
    # 1. From data_store['excel_columns'] if uploaded (filtering out internal helper keys)
    if data_store.get('excel_columns'):
        for c in data_store['excel_columns']:
            if c and c not in cols and not c.startswith('_') and c not in INTERNAL_KEYS:
                cols.append(c)

    # 2. Always ensure the standard 28 EXCEL_COLUMNS from Excel Columns.png are present in proper order
    for ec in EXCEL_COLUMNS:
        if ec not in cols:
            cols.append(ec)

    # Return {column_name: column_name} with exact casing
    return {c: c for c in cols}


@app.template_filter('get_cell')
def get_cell_value(row, col):
    """Retrieve cell value safely using direct key, MMQR alias, or normalized match."""
    if not isinstance(row, dict):
        return '-'
    if col in row and row[col] is not None and str(row[col]).strip() != '':
        return row[col]

    # 1. MMQR header -> internal alias
    if col in MMQR_COLUMN_MAP:
        int_key = MMQR_COLUMN_MAP[col]
        if int_key in row and row[int_key] is not None and str(row[int_key]).strip() != '':
            return row[int_key]

    # 2. Internal alias -> MMQR header
    for mmqr_k, int_k in MMQR_COLUMN_MAP.items():
        if int_k == col and mmqr_k in row and row[mmqr_k] is not None and str(row[mmqr_k]).strip() != '':
            return row[mmqr_k]

    # 3. Normalized match (e.g. 'Debitor Account' vs 'debitor_account')
    norm_col = col.lower().replace(' ', '_').replace('/', '_').replace('-', '_')
    for k, v in row.items():
        norm_k = str(k).lower().replace(' ', '_').replace('/', '_').replace('-', '_')
        if norm_k == norm_col and v is not None and str(v).strip() != '':
            return v

    return '-'


@app.template_filter('format_cell')
def format_cell_value(val, col=''):
    """Format cell value for display, handling numbers, amounts, dates, and strings."""
    if val is None or val == '' or val == '-':
        return '-'

    col_str = str(col).lower()
    is_amount = any(kw in col_str for kw in ['amount', 'mdr', 'fee', 'expense', 'income', 'balance', 'price'])
    if is_amount:
        try:
            cleaned = str(val).replace(',', '').strip()
            num = float(cleaned)
            if num % 1 == 0:
                return f"{int(num):,}"
            else:
                return f"{num:,.2f}"
        except (ValueError, TypeError):
            return str(val)

    if 'date' in col_str or 'time' in col_str:
        return str(val).strip()[:19]

    return str(val)


def analyze_hourly_counterparty_frequency(data, min_count=2):
    """
    Group transactions by Merchant -> 1-Hour Time Window -> Counterparty.
    Counts payment frequency within each 1-hour interval.
    (Sample from 9:00 AM to 10:00 AM by counterparty grouped under merchant).
    """
    if not data:
        return {
            'merchants': [],
            'summary': {
                'total_merchants': 0, 'total_groups': 0, 'total_txns': 0,
                'total_amount': 0, 'max_count': 0, 'peak_counterparty': '-',
                'peak_merchant': '-'
            },
            'available_hour_labels': []
        }

    from collections import defaultdict
    merch_tree = defaultdict(lambda: {
        'merchant_name': '',
        'merchant_no': '',
        'merchant_party': '',
        'slots': defaultdict(lambda: {
            'slot_key': '',
            'date_str': '',
            'hour_label': '',
            'counterparties': defaultdict(lambda: {
                'counterparty_name': '',
                'debitor_account': '',
                'customer_party': '',
                'phone_no': '',
                'transactions': []
            })
        })
    })

    for t in data:
        d_val = t.get('Transaction Date') or t.get('transaction_date')
        dt = safe_date(d_val)
        if not dt:
            continue
        h_start = dt.replace(minute=0, second=0)
        h_end = h_start + timedelta(hours=1)
        slot_key = f"{dt.strftime('%Y-%m-%d')} {h_start.strftime('%H:00')} - {h_end.strftime('%H:00')}"
        hour_label = f"{h_start.strftime('%I:%M %p')} - {h_end.strftime('%I:%M %p')}"
        date_str = dt.strftime('%Y-%m-%d')

        merch = t.get('Merchant Name') or t.get('Creditor Name') or t.get('merchant_name') or 'Unknown Merchant'
        cp = t.get('Debitor Name') or t.get('Customer Party') or t.get('counterparty') or 'Unknown Counterparty'

        m_entry = merch_tree[merch]
        m_entry['merchant_name'] = merch
        m_entry['merchant_no'] = t.get('Merchant No') or t.get('account_id') or ''
        m_entry['merchant_party'] = t.get('Merchant Party') or ''

        s_entry = m_entry['slots'][slot_key]
        s_entry['slot_key'] = slot_key
        s_entry['date_str'] = date_str
        s_entry['hour_label'] = hour_label

        cp_entry = s_entry['counterparties'][cp]
        cp_entry['counterparty_name'] = cp
        cp_entry['debitor_account'] = t.get('Debitor Account') or t.get('debitor_account') or ''
        cp_entry['customer_party'] = t.get('Customer Party') or t.get('customer_party') or ''
        cp_entry['phone_no'] = t.get('Phone No') or t.get('phone') or ''
        cp_entry['transactions'].append(t)

    final_merchants = []
    total_groups = 0
    total_txns = 0
    total_amount = 0
    max_count = 0
    peak_cp = '-'
    peak_merch = '-'
    group_counter = 0

    all_slots_set = set()

    for merch, m_data in sorted(merch_tree.items()):
        valid_slots = []
        merch_txn_count = 0
        merch_total_amount = 0

        for slot_key, s_data in sorted(m_data['slots'].items()):
            valid_cps = []
            for cp, cp_data in sorted(s_data['counterparties'].items()):
                cnt = len(cp_data['transactions'])
                if cnt >= min_count:
                    group_counter += 1
                    tot = sum(safe_float(x.get('Transaction Amount') or x.get('amount', 0)) for x in cp_data['transactions'])
                    group_id = f"grp_{group_counter}"
                    all_slots_set.add(s_data['hour_label'])

                    sorted_txns = sorted(
                        cp_data['transactions'],
                        key=lambda x: str(safe_date(x.get('Transaction Date') or x.get('transaction_date')) or '')
                    )

                    d_times = [safe_date(x.get('Transaction Date') or x.get('transaction_date')) for x in sorted_txns]
                    valid_d_times = [d for d in d_times if d]
                    min_time_str = valid_d_times[0].strftime('%H:%M:%S') if valid_d_times else ''
                    max_time_str = valid_d_times[-1].strftime('%H:%M:%S') if valid_d_times else ''

                    group_dict = {
                        'group_id': group_id,
                        'counterparty_name': cp_data['counterparty_name'],
                        'debitor_account': cp_data['debitor_account'],
                        'customer_party': cp_data['customer_party'],
                        'phone_no': cp_data['phone_no'],
                        'merchant_name': merch,
                        'merchant_no': m_data['merchant_no'],
                        'merchant_party': m_data['merchant_party'],
                        'slot_key': slot_key,
                        'hour_label': s_data['hour_label'],
                        'date_str': s_data['date_str'],
                        'count': cnt,
                        'total_amount': tot,
                        'avg_amount': tot / cnt if cnt else 0,
                        'min_time': min_time_str,
                        'max_time': max_time_str,
                        'severity': 'HIGH' if cnt >= 4 or tot >= 100000 else 'MEDIUM',
                        'transactions': sorted_txns
                    }
                    valid_cps.append(group_dict)
                    total_groups += 1
                    total_txns += cnt
                    total_amount += tot
                    merch_txn_count += cnt
                    merch_total_amount += tot
                    if cnt > max_count:
                        max_count = cnt
                        peak_cp = cp_data['counterparty_name']
                        peak_merch = merch

            if valid_cps:
                valid_cps.sort(key=lambda x: x['count'], reverse=True)
                valid_slots.append({
                    'slot_key': slot_key,
                    'date_str': s_data['date_str'],
                    'hour_label': s_data['hour_label'],
                    'counterparty_groups': valid_cps,
                    'slot_group_count': len(valid_cps)
                })

        if valid_slots:
            valid_slots.sort(key=lambda x: x['slot_key'], reverse=True)
            final_merchants.append({
                'merchant_name': m_data['merchant_name'],
                'merchant_no': m_data['merchant_no'],
                'merchant_party': m_data['merchant_party'],
                'slots': valid_slots,
                'total_groups': sum(len(s['counterparty_groups']) for s in valid_slots),
                'total_txns': merch_txn_count,
                'total_amount': merch_total_amount,
            })

    final_merchants.sort(key=lambda x: x['total_txns'], reverse=True)

    return {
        'merchants': final_merchants,
        'summary': {
            'total_merchants': len(final_merchants),
            'total_groups': total_groups,
            'total_txns': total_txns,
            'total_amount': total_amount,
            'max_count': max_count,
            'peak_counterparty': peak_cp,
            'peak_merchant': peak_merch,
        },
        'available_hour_labels': sorted(list(all_slots_set))
    }


META_FILE = os.path.join(app.config['UPLOAD_FOLDER'], 'data_store_meta.json')

def save_meta():
    try:
        meta = {
            'file_names': data_store.get('file_names', {}),
            'last_upload': data_store.get('last_upload'),
            'transaction_count': len(data_store.get('transactions', [])),
            'merchant_count': len(data_store.get('merchants', [])),
            'blacklist_count': len(data_store.get('blacklist', []))
        }
        with open(META_FILE, 'w', encoding='utf-8') as f:
            json.dump(meta, f, indent=2)
    except Exception as e:
        print("Error saving meta:", e)


def load_meta():
    if os.path.exists(META_FILE):
        try:
            with open(META_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def init_sample_data():
    """Auto-load existing sample/uploaded data files if present in data/."""
    upload_folder = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_folder, exist_ok=True)
    meta = load_meta()
    meta_files = meta.get('file_names', {})

    # 1. Transactions: Check meta first, or find newest Excel/CSV in data/
    txn_fn = meta_files.get('transactions')
    if not txn_fn or not os.path.exists(os.path.join(upload_folder, txn_fn)):
        # Prefer specific candidates or most recently modified transaction file
        candidates = []
        for f in os.listdir(upload_folder):
            if f.endswith(('.xlsx', '.xls', '.csv')):
                f_lower = f.lower()
                if not any(x in f_lower for x in ['blacklist', 'sample_merch', 'file_179']):
                    fp = os.path.join(upload_folder, f)
                    candidates.append((os.path.getmtime(fp), f))
        candidates.sort(reverse=True)
        if candidates:
            txn_fn = candidates[0][1]
        else:
            txn_fn = 'MMQR_Merchant_Transactions_01102026.xlsx'

    txn_fp = os.path.join(upload_folder, txn_fn)
    if os.path.exists(txn_fp):
        rows, headers = load_file(txn_fp)
        if rows:
            data_store['transactions'] = rows
            data_store['file_names']['transactions'] = txn_fn
            data_store['excel_columns'] = headers if headers else list(rows[0].keys())
            data_store['last_upload'] = datetime.fromtimestamp(os.path.getmtime(txn_fp)).strftime('%Y-%m-%d %H:%M:%S')
            cfg = load_config()
            if 'columns' not in cfg:
                cfg['columns'] = {}
            cfg['columns']['available'] = get_available_columns()
            save_config(cfg)
            print(f"Loaded {len(rows)} transactions from {txn_fn} with {len(data_store['excel_columns'])} columns")

    # 2. Merchants:
    merch_fn = meta_files.get('merchants') or 'sample_merchants.csv'
    merch_fp = os.path.join(upload_folder, merch_fn)
    if os.path.exists(merch_fp):
        rows, _ = load_file(merch_fp)
        if rows:
            data_store['merchants'] = rows
            data_store['file_names']['merchants'] = merch_fn

    # 3. Blacklist:
    bl_fn = meta_files.get('blacklist')
    if not bl_fn or not os.path.exists(os.path.join(upload_folder, bl_fn)):
        # Check if user uploaded file_1790843907255.xlsx exists
        if os.path.exists(os.path.join(upload_folder, 'file_1790843907255.xlsx')):
            bl_fn = 'file_1790843907255.xlsx'
        else:
            bl_fn = 'sample_blacklist.csv'
    bl_fp = os.path.join(upload_folder, bl_fn)
    if os.path.exists(bl_fp):
        rows, _ = load_file(bl_fp)
        if rows:
            data_store['blacklist'] = normalize_blacklist_rows(rows)
            data_store['file_names']['blacklist'] = bl_fn

    save_meta()


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
        processed_count = 0
        for field, target_key in [('transactions_file', 'transactions'), ('merchants_file', 'merchants'), ('blacklist_file', 'blacklist')]:
            f = request.files.get(field)
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                f.save(filepath)
                rows, headers = load_file(filepath)
                if not rows:
                    flash(f'File {filename} was empty or could not be parsed.', 'warning')
                    continue

                # Auto-detect actual file type
                actual_key = auto_detect_file_type(rows, headers, filename)
                if actual_key not in ('transactions', 'merchants', 'blacklist'):
                    actual_key = target_key

                if actual_key == 'blacklist':
                    rows = normalize_blacklist_rows(rows)

                data_store[actual_key] = rows
                data_store['file_names'][actual_key] = filename
                data_store['last_upload'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                processed_count += 1

                if actual_key == 'transactions':
                    data_store['excel_columns'] = headers if headers else (list(rows[0].keys()) if rows else [])
                    cfg = load_config()
                    if 'columns' not in cfg:
                        cfg['columns'] = {}
                    cfg['columns']['available'] = get_available_columns()
                    save_config(cfg)
                    flash(f'Transactions file loaded: {len(rows):,} records from {filename} ({len(headers)} columns detected)', 'success')
                    if is_mmqr_format(rows):
                        flash('MMQR format auto-detected & mapped! Columns are active in Reports and Settings.', 'info')
                elif actual_key == 'merchants':
                    flash(f'Merchants file loaded: {len(rows):,} merchants from {filename}', 'success')
                elif actual_key == 'blacklist':
                    flash(f'Blacklist file loaded: {len(rows):,} blacklisted entities from {filename}', 'success')

        if processed_count > 0:
            save_meta()
            return redirect(url_for('upload', _anchor='data-overview'))

    # Build comprehensive overview for upload.html
    txns = data_store.get('transactions', [])
    bl = data_store.get('blacklist', [])
    merch = data_store.get('merchants', [])

    total_txn_amount = sum(safe_float(r.get('Transaction Amount') or r.get('amount', 0)) for r in txns)
    dates = [safe_date(r.get('Transaction Date') or r.get('transaction_date')) for r in txns]
    valid_dates = [d for d in dates if d]
    min_date_str = valid_dates[0].strftime('%Y-%m-%d %H:%M:%S') if valid_dates else 'N/A'
    max_date_str = valid_dates[-1].strftime('%Y-%m-%d %H:%M:%S') if valid_dates else 'N/A'

    overview = {
        'transactions': {
            'count': len(txns),
            'filename': data_store['file_names'].get('transactions', 'None'),
            'columns_count': len(data_store.get('excel_columns', [])),
            'columns': data_store.get('excel_columns', []),
            'total_amount': total_txn_amount,
            'min_date': min_date_str,
            'max_date': max_date_str,
            'preview': txns[:8]
        },
        'merchants': {
            'count': len(merch),
            'filename': data_store['file_names'].get('merchants', 'None'),
            'preview': merch[:8]
        },
        'blacklist': {
            'count': len(bl),
            'filename': data_store['file_names'].get('blacklist', 'None'),
            'preview': bl[:8]
        },
        'last_upload': data_store.get('last_upload')
    }

    return render_template(
        'upload.html',
        file_names=data_store['file_names'],
        current_columns=data_store.get('excel_columns', []),
        overview=overview
    )


@app.route('/str')
def str_report():
    config = load_config()
    min_freq = request.args.get('min_freq', 2, type=int)
    results = detect_str(data_store['transactions'], config)
    hourly_data = analyze_hourly_counterparty_frequency(data_store['transactions'], min_count=min_freq)
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
    available = get_available_columns()
    visible_cols = config.get('columns', {}).get('str', DEFAULT_CONFIG['columns']['str'])
    return render_template(
        'str_report.html',
        results=results,
        summary=summary,
        visible_cols=visible_cols,
        available_cols=available,
        hourly_data=hourly_data,
        min_freq=min_freq
    )


@app.route('/api/hourly_group/<group_id>/csv')
def export_hourly_group_csv(group_id):
    hourly_data = analyze_hourly_counterparty_frequency(data_store['transactions'], min_count=1)
    target_group = None
    for m in hourly_data['merchants']:
        for s in m['slots']:
            for cp in s['counterparty_groups']:
                if cp['group_id'] == group_id:
                    target_group = cp
                    break
            if target_group:
                break
        if target_group:
            break

    if not target_group:
        flash('Group not found', 'error')
        return redirect(url_for('str_report'))

    config = load_config()
    visible_cols = config.get('columns', {}).get('str', DEFAULT_CONFIG['columns']['str'])
    headers = list(visible_cols.keys())

    output = []
    output.append(','.join([f'"{h}"' for h in headers]))
    for row in target_group['transactions']:
        vals = []
        for h in headers:
            v = get_cell_value(row, h)
            vals.append(f'"{str(v).replace(chr(34), chr(34)+chr(34))}"')
        output.append(','.join(vals))

    csv_data = '\r\n'.join(output)
    clean_cp = "".join(c for c in target_group['counterparty_name'] if c.isalnum() or c in (' ', '_', '-')).strip().replace(' ', '_')
    clean_slot = "".join(c for c in target_group['hour_label'] if c.isalnum() or c in ('-', '_')).strip()
    filename = f"HourlyGroup_{clean_cp}_{clean_slot}.csv"
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )


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
    available = get_available_columns()
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
        'total_blacklist_records': len(data_store['blacklist'])
    }
    return render_template(
        'blacklist.html',
        results=results,
        summary=summary,
        blacklist_records=data_store['blacklist'],
        blacklist_filename=data_store['file_names'].get('blacklist', 'None')
    )


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    config = load_config()
    available = get_available_columns()

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

        # Update column visibility for STR and TTR
        if 'columns' not in config:
            config['columns'] = {}

        # Get list of checked columns from form
        str_cols = request.form.getlist('str_columns')
        ttr_cols = request.form.getlist('ttr_columns')

        # Map to dict {column_name: display_label}
        config['columns']['str'] = {c: available.get(c, c) for c in str_cols}
        config['columns']['ttr'] = {c: available.get(c, c) for c in ttr_cols}
        config['columns']['available'] = available

        save_config(config)
        flash('Configuration and Column Visibility saved successfully!', 'success')
        return redirect(url_for('settings'))

    current_file = data_store['file_names'].get('transactions', 'Uploaded Excel / CSV')
    return render_template(
        'settings.html',
        config=config,
        available_cols=available,
        current_file=current_file,
        total_cols=len(available)
    )


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
    import argparse
    parser = argparse.ArgumentParser(description='Risk Management App')
    parser.add_argument('--port', type=int, default=3000, help='Port to run on')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to run on')
    args, _ = parser.parse_known_args()

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    init_sample_data()
    app.run(debug=False, host=args.host, port=args.port)
