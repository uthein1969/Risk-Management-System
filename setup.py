"""
Risk Management - One-Click Setup Script
Run: python setup.py
Then: python app.py
"""

import os

BASE = os.path.dirname(os.path.abspath(__file__))

def write_file(rel_path, content):
    path = os.path.join(BASE, rel_path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f'  ✅ {rel_path}')


# ─── requirements.txt ───
write_file('requirements.txt', '''flask==3.0.0
openpyxl==3.1.2
pandas==2.1.4
python-dateutil==2.8.2
werkzeug==3.0.1
''')

# ─── app.py ───
write_file('app.py', r'''import os, csv, json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'risk-management-secret-key-2026'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'data')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024
ALLOWED_EXTENSIONS = {'xlsx', 'xls', 'csv'}

data_store = {'transactions': [], 'merchants': [], 'blacklist': [], 'last_upload': None, 'file_names': {}}

def allowed_file(fn): return '.' in fn and fn.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def load_csv(fp):
    rows = []
    try:
        with open(fp, 'r', encoding='utf-8-sig') as f:
            for row in csv.DictReader(f):
                rows.append({k.strip(): v.strip() if v else '' for k, v in row.items()})
    except Exception as e: flash(f'CSV error: {e}', 'error')
    return rows

def load_excel(fp):
    try:
        import openpyxl
        wb = openpyxl.load_workbook(fp, read_only=True, data_only=True)
        ws = wb.active; rows = []; headers = []
        for i, row in enumerate(ws.iter_rows(values_only=True)):
            if i == 0: headers = [str(c).strip() if c else f'col_{j}' for j, c in enumerate(row)]
            else: rows.append({headers[j]: str(v).strip() if v else '' for j, v in enumerate(row) if j < len(headers)})
        wb.close(); return rows
    except Exception as e: flash(f'Excel error: {e}', 'error'); return []

def load_file(fp):
    ext = fp.rsplit('.',1)[1].lower() if '.' in fp else ''
    return load_csv(fp) if ext == 'csv' else load_excel(fp) if ext in ('xlsx','xls') else []

def sf(v, d=0):
    try: return float(str(v).replace(',',''))
    except: return d

def sd(v):
    for fmt in ('%Y-%m-%d %H:%M:%S','%Y-%m-%d'):
        try: return datetime.strptime(str(v)[:19], fmt)
        except: pass
    return None

def detect_str(data):
    if not data: return []
    res = []; th = 10000; lg = 50000
    by_acct = {}
    for r in data:
        a = r.get('account_id','')
        if a: by_acct.setdefault(a,[]).append(r)
    for r in data:
        tid = r.get('transaction_id',''); a = r.get('account_id',''); amt = sf(r.get('amount',0)); dt = sd(r.get('transaction_date'))
        if not tid or not a: continue
        if amt >= lg: res.append({'rule':'Large Transaction','severity':'MEDIUM','transaction_id':tid,'account_id':a,'amount':amt,'date':str(r.get('transaction_date',''))[:19],'details':f'Single txn {amt:,.0f} exceeds {lg:,}'})
        if amt > 0 and amt % 1000 == 0 and amt >= 5000: res.append({'rule':'Round Amount','severity':'LOW','transaction_id':tid,'account_id':a,'amount':amt,'date':str(r.get('transaction_date',''))[:19],'details':f'Round amount: {amt:,.0f}'})
    for a, txns in by_acct.items():
        dated = sorted([(t, sd(t.get('transaction_date'))) for t in txns if sd(t.get('transaction_date'))], key=lambda x: x[1])
        for i, (txn, dt) in enumerate(dated):
            win = [t for t, d in dated if d >= dt - timedelta(hours=24) and d <= dt]
            sm = [t for t in win if 0 < sf(t.get('amount',0)) < th]
            total = sum(sf(t.get('amount',0)) for t in sm)
            if len(sm) >= 3 and total > th: res.append({'rule':'Structuring','severity':'HIGH','transaction_id':txn.get('transaction_id',''),'account_id':a,'amount':sf(txn.get('amount',0)),'date':str(txn.get('transaction_date',''))[:19],'details':f'{len(sm)} txns totaling {total:,.0f} in 24h'})
            cnt = sum(1 for _, d in dated if d >= dt - timedelta(hours=1) and d <= dt)
            if cnt > 5: res.append({'rule':'High Frequency','severity':'HIGH','transaction_id':txn.get('transaction_id',''),'account_id':a,'amount':sf(txn.get('amount',0)),'date':str(txn.get('transaction_date',''))[:19],'details':f'{cnt} txns in 1 hour'})
    seen = set(); uniq = []
    for r in res:
        k = (r['transaction_id'], r['rule'])
        if k not in seen: seen.add(k); uniq.append(r)
    return uniq

def detect_ttr(data, th=10000):
    return [{**r, 'amount': sf(r.get('amount',0)), 'threshold': th, 'status': 'Pending Review'} for r in data if sf(r.get('amount',0)) >= th] if data else []

def inspect_kyc(data):
    if not data: return []
    hrt = ['money exchange','casino','crypto','pawnshop','night club','arms dealer']
    req = ['merchant_id','merchant_name','business_type','registration_date','owner_name','address','license_number','license_expiry']
    res = []
    for r in data:
        issues = []; rl = 'LOW'
        for f in req:
            if not r.get(f,'').strip(): issues.append(f'Missing: {f}')
        exp = r.get('license_expiry','')
        if exp:
            d = sd(exp)
            if d and d < datetime.now(): issues.append(f'License expired: {d.strftime("%Y-%m-%d")}'); rl = 'HIGH'
        bt = r.get('business_type','').lower()
        if any(h in bt for h in hrt): issues.append(f'High-risk: {r.get("business_type","")}'); rl = 'HIGH'
        reg = r.get('registration_date','')
        if reg:
            d = sd(reg)
            if d and (datetime.now()-d).days < 30: issues.append(f'New merchant ({(datetime.now()-d).days}d)'); rl = max(rl,'MEDIUM')
        if issues: res.append({'merchant_id':r.get('merchant_id',''),'merchant_name':r.get('merchant_name',''),'business_type':r.get('business_type',''),'risk_level':rl,'issue_count':len(issues),'; '.join(issues),'status':'Pending Review'})
    return res

def check_blacklist(txns, merch, bl):
    if not bl: return []
    res = []; ba = {r.get('account_id','') for r in bl if r.get('account_id')}; bm = {r.get('merchant_id','') for r in bl if r.get('merchant_id')}
    bn = {r.get('name','').lower() for r in bl if r.get('name')}; bp = {r.get('phone','') for r in bl if r.get('phone')}; bnrc = {r.get('nrc','') for r in bl if r.get('nrc')}
    for r in txns:
        m = []; a = r.get('account_id','')
        if a in ba: m.append(f'account_id: {a}')
        if m: res.append({'source':'Transaction','id':r.get('transaction_id',''),'name':a,'amount':sf(r.get('amount',0)),'matched_on':'; '.join(m),'severity':'CRITICAL','status':'Flagged'})
    for r in merch:
        m = []; mid = r.get('merchant_id','')
        if mid in bm: m.append(f'merchant_id: {mid}')
        if r.get('owner_name','').lower() in bn: m.append(f'owner: {r.get("owner_name","")}')
        if r.get('phone','') in bp: m.append(f'phone: {r.get("phone","")}')
        if r.get('nrc','') in bnrc: m.append(f'nrc: {r.get("nrc","")}')
        if m: res.append({'source':'Merchant','id':mid,'name':r.get('merchant_name',''),'amount':'-','matched_on':'; '.join(m),'severity':'CRITICAL','status':'Flagged'})
    return res

@app.route('/')
def dashboard():
    s = detect_str(data_store['transactions']); t = detect_ttr(data_store['transactions'])
    k = inspect_kyc(data_store['merchants']); b = check_blacklist(data_store['transactions'], data_store['merchants'], data_store['blacklist'])
    return render_template('dashboard.html', stats={'total_transactions':len(data_store['transactions']),'total_merchants':len(data_store['merchants']),'total_blacklist':len(data_store['blacklist']),'str_count':len(s),'ttr_count':len(t),'kyc_issues':len(k),'blacklist_hits':len(b),'last_upload':data_store['last_upload']})

@app.route('/upload', methods=['GET','POST'])
def upload():
    if request.method == 'POST':
        for field, key in [('transactions_file','transactions'),('merchants_file','merchants'),('blacklist_file','blacklist')]:
            f = request.files.get(field)
            if f and allowed_file(f.filename):
                fn = secure_filename(f.filename); fp = os.path.join(app.config['UPLOAD_FOLDER'], fn); f.save(fp)
                data_store[key] = load_file(fp); data_store['file_names'][key] = fn; data_store['last_upload'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                flash(f'{key.title()} loaded: {len(data_store[key])} rows', 'success')
        return redirect(url_for('upload'))
    return render_template('upload.html', file_names=data_store['file_names'])

@app.route('/str')
def str_report():
    r = detect_str(data_store['transactions'])
    s = {}
    if r:
        sevs = [x['severity'] for x in r]; rules = [x['rule'] for x in r]
        s = {'total':len(r),'high':sevs.count('HIGH'),'medium':sevs.count('MEDIUM'),'low':sevs.count('LOW'),'by_rule':{ru:rules.count(ru) for ru in set(rules)}}
    return render_template('str_report.html', results=r, summary=s)

@app.route('/ttr')
def ttr_report():
    th = request.args.get('threshold', 10000, type=float); r = detect_ttr(data_store['transactions'], th); s = {}
    if r:
        amts = [x['amount'] for x in r]; types = [x.get('transaction_type','') for x in r]
        s = {'total':len(r),'total_amount':sum(amts),'avg_amount':sum(amts)/len(amts),'by_type':{t:types.count(t) for t in set(types) if t}}
    return render_template('ttr_report.html', results=r, summary=s, threshold=th)

@app.route('/kyc')
def kyc_inspection():
    r = inspect_kyc(data_store['merchants']); s = {}
    if r:
        lvls = [x['risk_level'] for x in r]
        s = {'total':len(r),'high':lvls.count('HIGH'),'medium':lvls.count('MEDIUM'),'low':lvls.count('LOW')}
    return render_template('kyc_inspection.html', results=r, summary=s)

@app.route('/blacklist')
def blacklist_check():
    r = check_blacklist(data_store['transactions'], data_store['merchants'], data_store['blacklist'])
    srcs = [x['source'] for x in r]
    return render_template('blacklist.html', results=r, summary={'total_hits':len(r),'txn_hits':srcs.count('Transaction'),'merchant_hits':srcs.count('Merchant')})

@app.route('/api/stats')
def api_stats():
    sr = detect_str(data_store['transactions']); tr = detect_ttr(data_store['transactions']); kr = inspect_kyc(data_store['merchants'])
    sr_rules = [x['rule'] for x in sr]; tr_types = [x.get('transaction_type','') for x in tr]; kr_levels = [x['risk_level'] for x in kr]
    return jsonify({'str_by_rule':{r:sr_rules.count(r) for r in set(sr_rules)} if sr_rules else {},'ttr_by_type':{t:tr_types.count(t) for t in set(tr_types) if t} if tr_types else {},'kyc_by_level':{l:kr_levels.count(l) for l in set(kr_levels)} if kr_levels else {'HIGH':0,'MEDIUM':0,'LOW':0}})

@app.route('/download-template/<tt>')
def download_template(tt):
    tmpls = {'transactions':'transaction_id,account_id,amount,transaction_date,transaction_type,counterparty,currency\nTXN001,ACC001,5000,2026-08-01 10:30:00,Transfer,ACC005,MMK\n','merchants':'merchant_id,merchant_name,business_type,registration_date,owner_name,address,license_number,license_expiry,phone,nrc\nMERCH001,ABC Shop,Retail,2025-01-15,U Aung,123 Yangon,MEM-001,2027-06-30,09123456789,12/MAHA(N)123456\n','blacklist':'account_id,merchant_id,name,phone,nrc,reason,date_added\n,,U Bad Guy,09999999999,12/MAHA(N)99999,Fraud,2026-01-01\n'}
    if tt not in tmpls: flash('Not found','error'); return redirect(url_for('upload'))
    return Response(tmpls[tt], mimetype='text/csv', headers={'Content-Disposition':f'attachment; filename={tt}_template.csv'})

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=False, host='0.0.0.0', port=5000)
''')

# ─── generate_sample_data.py ───
write_file('generate_sample_data.py', r'''import csv, random, os
from datetime import datetime, timedelta
random.seed(42)
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(out, exist_ok=True)

def wc(fn, hdrs, rows):
    fp = os.path.join(out, fn)
    with open(fp, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=hdrs); w.writeheader(); w.writerows(rows)
    print(f'  ✅ {fn}: {len(rows)} rows')

accts = [f'ACC{str(i).zfill(3)}' for i in range(1,21)]
types = ['Transfer','Withdrawal','Deposit','Payment']
bd = datetime(2026,8,1)
rows = []
for i in range(200):
    td = bd + timedelta(days=random.randint(0,19), hours=random.randint(0,23), minutes=random.randint(0,59))
    amt = random.choice([round(random.uniform(100,9999),0), round(random.uniform(10000,49999),0), round(random.uniform(50000,200000),0), round(random.uniform(5000,9999),0), round(random.choice([5000,10000,20000,50000,100000]),0)])
    rows.append({'transaction_id':f'TXN{str(i+1).zfill(4)}','account_id':random.choice(accts),'amount':int(amt),'transaction_date':td.strftime('%Y-%m-%d %H:%M:%S'),'transaction_type':random.choice(types),'counterparty':f'ACC0{random.randint(50,69)}','currency':'MMK'})
sd = datetime(2026,8,15,10,0,0)
for j in range(6): rows.append({'transaction_id':f'TXN{str(201+j).zfill(4)}','account_id':'ACC005','amount':int(round(random.uniform(1500,4500),0)),'transaction_date':(sd+timedelta(hours=j)).strftime('%Y-%m-%d %H:%M:%S'),'transaction_type':'Transfer','counterparty':f'ACC0{random.randint(60,69)}','currency':'MMK'})
wc('sample_transactions.csv', ['transaction_id','account_id','amount','transaction_date','transaction_type','counterparty','currency'], rows)

btypes = ['Retail','Restaurant','Money Exchange','Casino','Crypto Exchange','Pawnshop','Night Club','Grocery','Electronics','Textile','Hotel','Travel Agency','Pharmacy','Auto Dealer','Arms Dealer']
merch = []
for i in range(30):
    rd = datetime(2023,1,1)+timedelta(days=random.randint(0,900)); le = rd+timedelta(days=random.choice([365,730,1095,-30,-100]))
    merch.append({'merchant_id':f'MERCH{str(i+1).zfill(3)}','merchant_name':f'Business {chr(65+i%26)}{i+1}','business_type':random.choice(btypes),'registration_date':rd.strftime('%Y-%m-%d'),'owner_name':f'U {random.choice(["Aung","Kyaw","Min","Hla","Tun"])} {random.choice(["Zaw","Oo","Naing","Aye","Lin"])}','address':f'{random.randint(1,200)} {random.choice(["Yangon","Mandalay","Naypyidaw","Bago"])}, Myanmar','license_number':f'MEM-{str(i+1).zfill(4)}','license_expiry':le.strftime('%Y-%m-%d'),'phone':f'09{random.randint(100000000,999999999)}','nrc':f'{random.randint(1,14)}/{random.choice(["MAHA","YAHA","BAHA"])}(N){random.randint(100000,999999)}'})
merch[5]['license_number'] = ''; merch[5]['address'] = ''; merch[10]['owner_name'] = ''; merch[15]['license_expiry'] = ''
wc('sample_merchants.csv', ['merchant_id','merchant_name','business_type','registration_date','owner_name','address','license_number','license_expiry','phone','nrc'], merch)

bl = [{'account_id':'ACC005','merchant_id':'','name':'U Bad Guy','phone':'09999999999','nrc':'12/MAHA(N)999999','reason':'Fraud','date_added':'2026-01-15'},{'account_id':'','merchant_id':'MERCH008','name':'Suspicious Shop','phone':'09888888888','nrc':'','reason':'Money Laundering','date_added':'2026-03-20'},{'account_id':'ACC012','merchant_id':'','name':'U Dark Money','phone':'09777777777','nrc':'5/BAHA(N)555555','reason':'Terrorism Financing','date_added':'2025-11-01'},{'account_id':'','merchant_id':'','name':'U Scam Master','phone':'09666666666','nrc':'7/YAHA(N)777777','reason':'Online Scam','date_added':'2026-05-10'}]
wc('sample_blacklist.csv', ['account_id','merchant_id','name','phone','nrc','reason','date_added'], bl)
print('\n🎉 Done!')
''')

# ─── static/css/style.css ───
write_file('static/css/style.css', r''':root{--sidebar-width:260px;--topbar-height:56px;--sidebar-bg:#1a1d23;--sidebar-active:#0d6efd}*{box-sizing:border-box}body{margin:0;padding:0;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;overflow-x:hidden}
.sidebar{position:fixed;top:0;left:0;width:var(--sidebar-width);height:100vh;background:var(--sidebar-bg);color:#fff;display:flex;flex-direction:column;z-index:1000;transition:transform .3s ease}.sidebar.collapsed{transform:translateX(-100%)}
.sidebar-header{padding:1.25rem 1rem;font-size:1.1rem;font-weight:700;display:flex;align-items:center;gap:.75rem;border-bottom:1px solid rgba(255,255,255,.1)}.sidebar-header i{font-size:1.5rem;color:#0d6efd}
.sidebar-nav{list-style:none;padding:.5rem 0;margin:0;flex:1;overflow-y:auto}.sidebar-nav .nav-item .nav-link{display:flex;align-items:center;gap:.75rem;padding:.65rem 1rem;color:rgba(255,255,255,.7);text-decoration:none;transition:all .2s;font-size:.9rem}.sidebar-nav .nav-item .nav-link:hover{color:#fff;background:rgba(255,255,255,.08)}.sidebar-nav .nav-item .nav-link.active{color:#fff;background:var(--sidebar-active)}.sidebar-nav .nav-link i{width:1.25rem;text-align:center;font-size:1rem}
.nav-divider{padding:.75rem 1rem .25rem;font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:rgba(255,255,255,.35);font-weight:600}
.sidebar-footer{padding:.75rem 1rem;border-top:1px solid rgba(255,255,255,.1);color:rgba(255,255,255,.4);font-size:.75rem}
.main-content{margin-left:var(--sidebar-width);min-height:100vh;transition:margin-left .3s ease}.main-content.expanded{margin-left:0}
.topbar{height:var(--topbar-height);padding:0 1.5rem;display:flex;align-items:center;gap:1rem;border-bottom:1px solid var(--bs-border-color);background:var(--bs-body-bg);position:sticky;top:0;z-index:100}.topbar h5{font-weight:600}.sidebar-toggle{font-size:1.25rem;color:var(--bs-body-color);text-decoration:none}
.content-wrapper{padding:1.5rem}
.stat-card{border-width:2px;transition:transform .15s,box-shadow .15s}.stat-card:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.15)}.stat-icon{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:1.25rem}
.upload-area{border:2px dashed var(--bs-border-color);border-radius:12px;padding:2rem;text-align:center;transition:border-color .2s,background .2s;cursor:pointer}.upload-area:hover{border-color:var(--bs-primary);background:rgba(13,110,253,.05)}.upload-placeholder i{display:block;margin-bottom:.5rem}.upload-selected{display:flex;align-items:center;gap:1rem;padding:.5rem}
.table{font-size:.875rem}.table th{font-weight:600;text-transform:uppercase;font-size:.75rem;letter-spacing:.05em;color:var(--bs-secondary-color);border-bottom-width:2px}.table td{vertical-align:middle}.table code{font-size:.8rem}
.badge{font-weight:600;font-size:.7rem;letter-spacing:.03em}.card{border-radius:12px}.card-header{font-weight:600}
@media(max-width:768px){.sidebar{transform:translateX(-100%)}.sidebar.show{transform:translateX(0)}.main-content{margin-left:0!important}.content-wrapper{padding:1rem}.topbar{padding:0 1rem}}
::-webkit-scrollbar{width:6px;height:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:rgba(128,128,128,.3);border-radius:3px}::-webkit-scrollbar-thumb:hover{background:rgba(128,128,128,.5)}
@media print{.sidebar,.topbar,.sidebar-toggle{display:none!important}.main-content{margin-left:0!important}}
''')

# ─── static/js/main.js ───
write_file('static/js/main.js', r'''function toggleSidebar(){const s=document.getElementById('sidebar'),m=document.querySelector('.main-content');if(window.innerWidth<=768)s.classList.toggle('show');else{s.classList.toggle('collapsed');m.classList.toggle('expanded')}}
document.addEventListener('click',e=>{if(window.innerWidth<=768){const s=document.getElementById('sidebar');if(!s.contains(e.target)&&!e.target.closest('.sidebar-toggle'))s.classList.remove('show')}});
function exportTableCSV(tid,fn){const t=document.getElementById(tid);if(!t)return;const rows=[],h=[];t.querySelectorAll('thead th').forEach(th=>h.push(th.textContent.trim()));rows.push(h.join(','));t.querySelectorAll('tbody tr').forEach(tr=>{if(tr.style.display==='none')return;const c=[];tr.querySelectorAll('td').forEach(td=>{let v=td.textContent.trim().replace(/"/g,'""');c.push(`"${v}"`)});rows.push(c.join(','))});const blob=new Blob(['\ufeff'+rows.join('\n')],{type:'text/csv;charset=utf-8;'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=`${fn}_${new Date().toISOString().slice(0,10)}.csv`;a.click()}
document.addEventListener('DOMContentLoaded',()=>{document.querySelectorAll('.alert-dismissible').forEach(a=>{setTimeout(()=>{bootstrap.Alert.getOrCreateInstance(a).close()},5000)})});
document.querySelectorAll('.upload-area').forEach(a=>{a.addEventListener('dragover',e=>{e.preventDefault();a.style.borderColor='var(--bs-primary)';a.style.background='rgba(13,110,253,.08)'});a.addEventListener('dragleave',()=>{a.style.borderColor='';a.style.background=''});a.addEventListener('drop',e=>{e.preventDefault();a.style.borderColor='';a.style.background='';const fi=a.querySelector('input[type="file"]');if(fi&&e.dataTransfer.files.length>0){fi.files=e.dataTransfer.files;fi.dispatchEvent(new Event('change'))}})});
''')

# ─── Templates ───
write_file('templates/base.html', r'''<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>{% block title %}Risk Management{% endblock %}</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.2/font/bootstrap-icons.min.css" rel="stylesheet"><link href="{{ url_for('static',filename='css/style.css') }}" rel="stylesheet"></head>
<body>
<nav class="sidebar" id="sidebar"><div class="sidebar-header"><i class="bi bi-shield-check"></i><span>Risk Management</span></div><ul class="sidebar-nav"><li class="nav-item"><a href="{{ url_for('dashboard') }}" class="nav-link {% if request.endpoint=='dashboard' %}active{% endif %}"><i class="bi bi-speedometer2"></i> Dashboard</a></li><li class="nav-item"><a href="{{ url_for('upload') }}" class="nav-link {% if request.endpoint=='upload' %}active{% endif %}"><i class="bi bi-cloud-upload"></i> Upload Data</a></li><li class="nav-divider">Reports</li><li class="nav-item"><a href="{{ url_for('str_report') }}" class="nav-link {% if request.endpoint=='str_report' %}active{% endif %}"><i class="bi bi-exclamation-triangle"></i> STR Report</a></li><li class="nav-item"><a href="{{ url_for('ttr_report') }}" class="nav-link {% if request.endpoint=='ttr_report' %}active{% endif %}"><i class="bi bi-cash-stack"></i> TTR Report</a></li><li class="nav-item"><a href="{{ url_for('kyc_inspection') }}" class="nav-link {% if request.endpoint=='kyc_inspection' %}active{% endif %}"><i class="bi bi-person-check"></i> KYC Inspection</a></li><li class="nav-item"><a href="{{ url_for('blacklist_check') }}" class="nav-link {% if request.endpoint=='blacklist_check' %}active{% endif %}"><i class="bi bi-person-x"></i> Blacklist</a></li></ul><div class="sidebar-footer"><small>v1.0 · Risk Management System</small></div></nav>
<main class="main-content"><div class="topbar"><button class="btn btn-link sidebar-toggle" onclick="toggleSidebar()"><i class="bi bi-list"></i></button><h5 class="mb-0">{% block page_title %}Dashboard{% endblock %}</h5><div class="ms-auto d-flex align-items-center gap-2">{% block page_actions %}{% endblock %}</div></div>
{% with messages = get_flashed_messages(with_categories=true) %}{% if messages %}{% for cat, msg in messages %}<div class="alert alert-{{ 'danger' if cat=='error' else cat }} alert-dismissible fade show mx-3 mt-2" role="alert">{{ msg }}<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>{% endfor %}{% endif %}{% endwith %}
<div class="content-wrapper">{% block content %}{% endblock %}</div></main>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script><script src="{{ url_for('static',filename='js/main.js') }}"></script>{% block extra_js %}{% endblock %}
</body></html>
''')

write_file('templates/dashboard.html', r'''{% extends "base.html" %}{% block title %}Dashboard{% endblock %}{% block page_title %}Dashboard{% endblock %}
{% block content %}<div class="container-fluid"><div class="row g-3 mb-4">
<div class="col-md-3"><div class="card stat-card border-primary"><div class="card-body"><div class="d-flex justify-content-between align-items-center"><div><h6 class="text-muted mb-1">Total Transactions</h6><h3 class="mb-0">{{ stats.total_transactions }}</h3></div><div class="stat-icon bg-primary-subtle"><i class="bi bi-arrow-left-right text-primary"></i></div></div></div></div></div>
<div class="col-md-3"><div class="card stat-card border-warning"><div class="card-body"><div class="d-flex justify-content-between align-items-center"><div><h6 class="text-muted mb-1">STR Alerts</h6><h3 class="mb-0 text-warning">{{ stats.str_count }}</h3></div><div class="stat-icon bg-warning-subtle"><i class="bi bi-exclamation-triangle text-warning"></i></div></div></div></div></div>
<div class="col-md-3"><div class="card stat-card border-danger"><div class="card-body"><div class="d-flex justify-content-between align-items-center"><div><h6 class="text-muted mb-1">TTR Flagged</h6><h3 class="mb-0 text-danger">{{ stats.ttr_count }}</h3></div><div class="stat-icon bg-danger-subtle"><i class="bi bi-cash-stack text-danger"></i></div></div></div></div></div>
<div class="col-md-3"><div class="card stat-card border-info"><div class="card-body"><div class="d-flex justify-content-between align-items-center"><div><h6 class="text-muted mb-1">Merchants</h6><h3 class="mb-0">{{ stats.total_merchants }}</h3></div><div class="stat-icon bg-info-subtle"><i class="bi bi-shop text-info"></i></div></div></div></div></div>
</div><div class="row g-3 mb-4">
<div class="col-md-4"><div class="card stat-card border-warning"><div class="card-body"><div class="d-flex justify-content-between align-items-center"><div><h6 class="text-muted mb-1">KYC Issues</h6><h3 class="mb-0 text-warning">{{ stats.kyc_issues }}</h3></div><div class="stat-icon bg-warning-subtle"><i class="bi bi-person-exclamation text-warning"></i></div></div></div></div></div>
<div class="col-md-4"><div class="card stat-card border-danger"><div class="card-body"><div class="d-flex justify-content-between align-items-center"><div><h6 class="text-muted mb-1">Blacklist Hits</h6><h3 class="mb-0 text-danger">{{ stats.blacklist_hits }}</h3></div><div class="stat-icon bg-danger-subtle"><i class="bi bi-person-x text-danger"></i></div></div></div></div></div>
<div class="col-md-4"><div class="card stat-card border-secondary"><div class="card-body"><div class="d-flex justify-content-between align-items-center"><div><h6 class="text-muted mb-1">Blacklist Entries</h6><h3 class="mb-0">{{ stats.total_blacklist }}</h3></div><div class="stat-icon bg-secondary-subtle"><i class="bi bi-database text-secondary"></i></div></div></div></div></div>
</div><div class="row g-3"><div class="col-md-6"><div class="card"><div class="card-header"><h6 class="mb-0"><i class="bi bi-lightning-charge"></i> Quick Actions</h6></div><div class="card-body"><div class="d-grid gap-2"><a href="{{ url_for('upload') }}" class="btn btn-outline-primary"><i class="bi bi-cloud-upload"></i> Upload New Data</a><div class="row g-2"><div class="col-6"><a href="{{ url_for('str_report') }}" class="btn btn-outline-warning w-100"><i class="bi bi-exclamation-triangle"></i> STR Analysis</a></div><div class="col-6"><a href="{{ url_for('ttr_report') }}" class="btn btn-outline-danger w-100"><i class="bi bi-cash-stack"></i> TTR Check</a></div><div class="col-6"><a href="{{ url_for('kyc_inspection') }}" class="btn btn-outline-info w-100"><i class="bi bi-person-check"></i> KYC Inspection</a></div><div class="col-6"><a href="{{ url_for('blacklist_check') }}" class="btn btn-outline-secondary w-100"><i class="bi bi-person-x"></i> Blacklist Check</a></div></div></div></div></div></div>
<div class="col-md-6"><div class="card"><div class="card-header"><h6 class="mb-0"><i class="bi bi-info-circle"></i> System Status</h6></div><div class="card-body"><table class="table table-sm mb-0"><tr><td class="text-muted">Last Upload</td><td class="text-end">{{ stats.last_upload or 'Never' }}</td></tr><tr><td class="text-muted">Transactions</td><td class="text-end">{% if stats.total_transactions > 0 %}<span class="badge bg-success">Loaded</span>{% else %}<span class="badge bg-secondary">Not loaded</span>{% endif %}</td></tr><tr><td class="text-muted">Merchants</td><td class="text-end">{% if stats.total_merchants > 0 %}<span class="badge bg-success">Loaded</span>{% else %}<span class="badge bg-secondary">Not loaded</span>{% endif %}</td></tr><tr><td class="text-muted">Blacklist</td><td class="text-end">{% if stats.total_blacklist > 0 %}<span class="badge bg-success">Loaded</span>{% else %}<span class="badge bg-secondary">Not loaded</span>{% endif %}</td></tr></table></div></div></div></div></div>{% endblock %}
''')

write_file('templates/upload.html', r'''{% extends "base.html" %}{% block title %}Upload Data{% endblock %}{% block page_title %}Upload Data{% endblock %}
{% block content %}<div class="container-fluid"><div class="row g-4"><div class="col-lg-8"><form method="POST" enctype="multipart/form-data"><div class="card mb-4"><div class="card-header"><h6 class="mb-0"><i class="bi bi-file-earmark-excel"></i> Upload Data Files</h6></div><div class="card-body"><p class="text-muted mb-4">Upload .xlsx or .csv files for risk analysis.</p>
<div class="upload-section mb-4"><label class="form-label fw-bold"><i class="bi bi-arrow-left-right text-primary"></i> Transactions</label><div class="upload-area"><input type="file" name="transactions_file" accept=".xlsx,.xls,.csv" class="d-none" id="txnFile" onchange="handleFileSelect(this,'txn')"><div class="upload-placeholder" onclick="document.getElementById('txnFile').click()"><i class="bi bi-cloud-arrow-up fs-1 text-primary"></i><p class="mb-1">Click to upload (.xlsx / .csv)</p><small class="text-muted">Required: transaction_id, account_id, amount, transaction_date, transaction_type</small></div><div class="upload-selected d-none" id="txnSelected"><i class="bi bi-file-earmark-excel text-success fs-3"></i><div><p class="mb-0 fw-bold" id="txnFileName">-</p><small class="text-muted" id="txnFileSize">-</small></div><button type="button" class="btn btn-sm btn-outline-danger ms-auto" onclick="clearFile('txn')"><i class="bi bi-x"></i></button></div></div><a href="{{ url_for('download_template',template_type='transactions') }}" class="btn btn-sm btn-link px-0"><i class="bi bi-download"></i> Download template</a></div>
<div class="upload-section mb-4"><label class="form-label fw-bold"><i class="bi bi-shop text-info"></i> Merchants</label><div class="upload-area"><input type="file" name="merchants_file" accept=".xlsx,.xls,.csv" class="d-none" id="merchantFile" onchange="handleFileSelect(this,'merchant')"><div class="upload-placeholder" onclick="document.getElementById('merchantFile').click()"><i class="bi bi-cloud-arrow-up fs-1 text-info"></i><p class="mb-1">Click to upload (.xlsx / .csv)</p><small class="text-muted">Required: merchant_id, merchant_name, business_type, registration_date, owner_name, license_number, license_expiry</small></div><div class="upload-selected d-none" id="merchantSelected"><i class="bi bi-file-earmark-excel text-success fs-3"></i><div><p class="mb-0 fw-bold" id="merchantFileName">-</p><small class="text-muted" id="merchantFileSize">-</small></div><button type="button" class="btn btn-sm btn-outline-danger ms-auto" onclick="clearFile('merchant')"><i class="bi bi-x"></i></button></div></div><a href="{{ url_for('download_template',template_type='merchants') }}" class="btn btn-sm btn-link px-0"><i class="bi bi-download"></i> Download template</a></div>
<div class="upload-section mb-4"><label class="form-label fw-bold"><i class="bi bi-person-x text-danger"></i> Blacklist</label><div class="upload-area"><input type="file" name="blacklist_file" accept=".xlsx,.xls,.csv" class="d-none" id="blFile" onchange="handleFileSelect(this,'bl')"><div class="upload-placeholder" onclick="document.getElementById('blFile').click()"><i class="bi bi-cloud-arrow-up fs-1 text-danger"></i><p class="mb-1">Click to upload (.xlsx / .csv)</p><small class="text-muted">Columns: account_id, merchant_id, name, phone, nrc, reason, date_added</small></div><div class="upload-selected d-none" id="blSelected"><i class="bi bi-file-earmark-excel text-success fs-3"></i><div><p class="mb-0 fw-bold" id="blFileName">-</p><small class="text-muted" id="blFileSize">-</small></div><button type="button" class="btn btn-sm btn-outline-danger ms-auto" onclick="clearFile('bl')"><i class="bi bi-x"></i></button></div></div><a href="{{ url_for('download_template',template_type='blacklist') }}" class="btn btn-sm btn-link px-0"><i class="bi bi-download"></i> Download template</a></div>
</div><div class="card-footer"><button type="submit" class="btn btn-primary"><i class="bi bi-upload"></i> Upload & Analyze</button></div></div></form></div>
<div class="col-lg-4"><div class="card mb-4"><div class="card-header"><h6 class="mb-0"><i class="bi bi-info-circle"></i> File Requirements</h6></div><div class="card-body"><h6 class="text-primary">Transactions</h6><ul class="small mb-3"><li><code>transaction_id</code> - Unique ID</li><li><code>account_id</code> - Account identifier</li><li><code>amount</code> - Transaction amount</li><li><code>transaction_date</code> - Date (YYYY-MM-DD)</li><li><code>transaction_type</code> - Transfer/Withdrawal/Deposit</li></ul><h6 class="text-info">Merchants</h6><ul class="small mb-3"><li><code>merchant_id</code> - Unique ID</li><li><code>merchant_name</code> - Business name</li><li><code>business_type</code> - Type</li><li><code>owner_name</code> - Owner</li><li><code>license_number</code> / <code>license_expiry</code></li></ul><h6 class="text-danger">Blacklist</h6><ul class="small mb-0"><li><code>account_id</code> / <code>merchant_id</code></li><li><code>name</code> / <code>phone</code> / <code>nrc</code></li><li><code>reason</code> / <code>date_added</code></li></ul></div></div>
{% if file_names %}<div class="card"><div class="card-header"><h6 class="mb-0"><i class="bi bi-folder"></i> Currently Loaded</h6></div><div class="card-body">{% if file_names.get('transactions') %}<p class="mb-1"><i class="bi bi-check-circle text-success"></i> <strong>Transactions:</strong> {{ file_names.transactions }}</p>{% endif %}{% if file_names.get('merchants') %}<p class="mb-1"><i class="bi bi-check-circle text-success"></i> <strong>Merchants:</strong> {{ file_names.merchants }}</p>{% endif %}{% if file_names.get('blacklist') %}<p class="mb-0"><i class="bi bi-check-circle text-success"></i> <strong>Blacklist:</strong> {{ file_names.blacklist }}</p>{% endif %}</div></div>{% endif %}</div></div></div>{% endblock %}
{% block extra_js %}<script>function handleFileSelect(i,p){if(i.files.length>0){const f=i.files[0];document.getElementById(p+'Selected').classList.remove('d-none');document.getElementById(p+'Selected').previousElementSibling.classList.add('d-none');document.getElementById(p+'FileName').textContent=f.name;document.getElementById(p+'FileSize').textContent=f.size<1024?f.size+' B':f.size<1048576?(f.size/1024).toFixed(1)+' KB':(f.size/1048576).toFixed(1)+' MB'}}function clearFile(p){document.getElementById(p+'File').value='';document.getElementById(p+'Selected').classList.add('d-none');document.getElementById(p+'Selected').previousElementSibling.classList.remove('d-none')}</script>{% endblock %}
''')

write_file('templates/str_report.html', r'''{% extends "base.html" %}{% block title %}STR Report{% endblock %}{% block page_title %}STR - Suspicious Transaction Report{% endblock %}
{% block content %}<div class="container-fluid">{% if summary %}<div class="row g-3 mb-4">
<div class="col-md-3"><div class="card stat-card border-danger"><div class="card-body text-center"><h2 class="text-danger mb-0">{{ summary.total }}</h2><small class="text-muted">Total Suspicious</small></div></div></div>
<div class="col-md-3"><div class="card stat-card border-danger"><div class="card-body text-center"><h2 class="text-danger mb-0">{{ summary.high }}</h2><small class="text-muted">HIGH</small></div></div></div>
<div class="col-md-3"><div class="card stat-card border-warning"><div class="card-body text-center"><h2 class="text-warning mb-0">{{ summary.medium }}</h2><small class="text-muted">MEDIUM</small></div></div></div>
<div class="col-md-3"><div class="card stat-card border-info"><div class="card-body text-center"><h2 class="text-info mb-0">{{ summary.low }}</h2><small class="text-muted">LOW</small></div></div></div>
</div>{% if summary.by_rule %}<div class="card mb-4"><div class="card-header"><h6 class="mb-0"><i class="bi bi-bar-chart"></i> Rules Breakdown</h6></div><div class="card-body"><div class="row">{% for rule, count in summary.by_rule.items() %}<div class="col-md-3 mb-2"><div class="d-flex justify-content-between align-items-center p-2 bg-body-secondary rounded"><span>{{ rule }}</span><span class="badge bg-danger">{{ count }}</span></div></div>{% endfor %}</div></div></div>{% endif %}{% endif %}
<div class="card mb-4"><div class="card-body"><div class="row g-2 align-items-center"><div class="col-auto"><select class="form-select form-select-sm" id="severityFilter" onchange="filterTable()"><option value="">All Severity</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option></select></div><div class="col-auto"><input type="text" class="form-control form-control-sm" id="searchInput" placeholder="Search..." onkeyup="filterTable()"></div><div class="col-auto ms-auto"><button class="btn btn-sm btn-outline-success" onclick="exportTableCSV('strTable','str_report')"><i class="bi bi-download"></i> Export CSV</button></div></div></div></div>
<div class="card"><div class="card-body table-responsive">{% if results %}<table class="table table-hover table-sm" id="strTable"><thead><tr><th>#</th><th>Severity</th><th>Rule</th><th>Txn ID</th><th>Account</th><th>Amount</th><th>Date</th><th>Details</th></tr></thead><tbody>{% for r in results %}<tr data-severity="{{ r.severity }}"><td>{{ loop.index }}</td><td>{% if r.severity=='HIGH' %}<span class="badge bg-danger">HIGH</span>{% elif r.severity=='MEDIUM' %}<span class="badge bg-warning text-dark">MEDIUM</span>{% else %}<span class="badge bg-info">LOW</span>{% endif %}</td><td>{{ r.rule }}</td><td><code>{{ r.transaction_id }}</code></td><td>{{ r.account_id }}</td><td class="text-end">{{ "{:,.0f}".format(r.amount) }}</td><td>{{ r.date[:10] if r.date else '-' }}</td><td class="small">{{ r.details }}</td></tr>{% endfor %}</tbody></table>{% else %}<div class="text-center py-5"><i class="bi bi-shield-check fs-1 text-success"></i><h5 class="mt-3">No Suspicious Transactions</h5><a href="{{ url_for('upload') }}" class="btn btn-primary">Upload Data</a></div>{% endif %}</div></div></div>{% endblock %}
{% block extra_js %}<script>function filterTable(){const s=document.getElementById('severityFilter').value,q=document.getElementById('searchInput').value.toLowerCase();document.querySelectorAll('#strTable tbody tr').forEach(r=>{r.style.display=(!s||r.dataset.severity===s)&&(!q||r.textContent.toLowerCase().includes(q))?'':'none'})}</script>{% endblock %}
''')

write_file('templates/ttr_report.html', r'''{% extends "base.html" %}{% block title %}TTR Report{% endblock %}{% block page_title %}TTR - Threshold Transaction Report{% endblock %}
{% block page_actions %}<form class="d-flex align-items-center gap-2" method="GET"><label class="form-label mb-0 small text-nowrap">Threshold:</label><input type="number" name="threshold" value="{{ threshold }}" class="form-control form-control-sm" style="width:130px" step="1000" min="0"><button type="submit" class="btn btn-sm btn-primary">Apply</button></form>{% endblock %}
{% block content %}<div class="container-fluid">{% if summary %}<div class="row g-3 mb-4">
<div class="col-md-3"><div class="card stat-card border-danger"><div class="card-body text-center"><h2 class="text-danger mb-0">{{ summary.total }}</h2><small class="text-muted">Flagged</small></div></div></div>
<div class="col-md-3"><div class="card stat-card border-warning"><div class="card-body text-center"><h2 class="text-warning mb-0">{{ "{:,.0f}".format(summary.total_amount) }}</h2><small class="text-muted">Total Amount</small></div></div></div>
<div class="col-md-3"><div class="card stat-card border-info"><div class="card-body text-center"><h2 class="text-info mb-0">{{ "{:,.0f}".format(summary.avg_amount) }}</h2><small class="text-muted">Average</small></div></div></div>
<div class="col-md-3"><div class="card stat-card border-secondary"><div class="card-body text-center"><h2 class="mb-0">{{ "{:,.0f}".format(threshold) }}</h2><small class="text-muted">Threshold</small></div></div></div>
</div>{% endif %}
<div class="card mb-4"><div class="card-body"><div class="row g-2 align-items-center"><div class="col-auto"><input type="text" class="form-control form-control-sm" id="ttrSearch" placeholder="Search..." onkeyup="filterTTR()"></div><div class="col-auto ms-auto"><button class="btn btn-sm btn-outline-success" onclick="exportTableCSV('ttrTable','ttr_report')"><i class="bi bi-download"></i> Export</button></div></div></div></div>
<div class="card"><div class="card-body table-responsive">{% if results %}<table class="table table-hover table-sm" id="ttrTable"><thead><tr><th>#</th><th>Txn ID</th><th>Account</th><th>Type</th><th class="text-end">Amount</th><th>Date</th><th>Status</th></tr></thead><tbody>{% for r in results %}<tr><td>{{ loop.index }}</td><td><code>{{ r.get('transaction_id','-') }}</code></td><td>{{ r.get('account_id','-') }}</td><td>{{ r.get('transaction_type','-') }}</td><td class="text-end fw-bold text-danger">{{ "{:,.0f}".format(r.amount) }}</td><td>{{ r.get('transaction_date','-')[:10] }}</td><td><span class="badge bg-warning text-dark">{{ r.status }}</span></td></tr>{% endfor %}</tbody></table>{% else %}<div class="text-center py-5"><i class="bi bi-cash-stack fs-1 text-success"></i><h5 class="mt-3">No Transactions Above Threshold</h5><a href="{{ url_for('upload') }}" class="btn btn-primary">Upload Data</a></div>{% endif %}</div></div></div>{% endblock %}
{% block extra_js %}<script>function filterTTR(){const q=document.getElementById('ttrSearch').value.toLowerCase();document.querySelectorAll('#ttrTable tbody tr').forEach(r=>{r.style.display=r.textContent.toLowerCase().includes(q)?'':'none'})}</script>{% endblock %}
''')

write_file('templates/kyc_inspection.html', r'''{% extends "base.html" %}{% block title %}KYC Inspection{% endblock %}{% block page_title %}Merchant KYC Inspection{% endblock %}
{% block content %}<div class="container-fluid">{% if summary %}<div class="row g-3 mb-4">
<div class="col-md-4"><div class="card stat-card border-danger"><div class="card-body text-center"><h2 class="text-danger mb-0">{{ summary.high }}</h2><small class="text-muted">HIGH Risk</small></div></div></div>
<div class="col-md-4"><div class="card stat-card border-warning"><div class="card-body text-center"><h2 class="text-warning mb-0">{{ summary.medium }}</h2><small class="text-muted">MEDIUM Risk</small></div></div></div>
<div class="col-md-4"><div class="card stat-card border-success"><div class="card-body text-center"><h2 class="text-success mb-0">{{ summary.low }}</h2><small class="text-muted">LOW Risk</small></div></div></div>
</div>{% endif %}
<div class="card mb-4"><div class="card-body"><div class="row g-2 align-items-center"><div class="col-auto"><select class="form-select form-select-sm" id="kycRiskFilter" onchange="filterKYC()"><option value="">All Risk</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option><option value="LOW">LOW</option></select></div><div class="col-auto"><input type="text" class="form-control form-control-sm" id="kycSearch" placeholder="Search..." onkeyup="filterKYC()"></div><div class="col-auto ms-auto"><button class="btn btn-sm btn-outline-success" onclick="exportTableCSV('kycTable','kyc_inspection')"><i class="bi bi-download"></i> Export</button></div></div></div></div>
<div class="card"><div class="card-body table-responsive">{% if results %}<table class="table table-hover table-sm" id="kycTable"><thead><tr><th>#</th><th>Risk</th><th>Merchant ID</th><th>Name</th><th>Business Type</th><th>Issues</th><th>Count</th><th>Status</th></tr></thead><tbody>{% for r in results %}<tr data-risk="{{ r.risk_level }}"><td>{{ loop.index }}</td><td>{% if r.risk_level=='HIGH' %}<span class="badge bg-danger">HIGH</span>{% elif r.risk_level=='MEDIUM' %}<span class="badge bg-warning text-dark">MEDIUM</span>{% else %}<span class="badge bg-success">LOW</span>{% endif %}</td><td><code>{{ r.merchant_id }}</code></td><td>{{ r.merchant_name }}</td><td>{{ r.business_type }}</td><td class="small">{{ r.issues }}</td><td class="text-center">{{ r.issue_count }}</td><td><span class="badge bg-warning text-dark">{{ r.status }}</span></td></tr>{% endfor %}</tbody></table>{% else %}<div class="text-center py-5"><i class="bi bi-person-check fs-1 text-success"></i><h5 class="mt-3">No KYC Issues</h5><a href="{{ url_for('upload') }}" class="btn btn-primary">Upload Data</a></div>{% endif %}</div></div></div>{% endblock %}
{% block extra_js %}<script>function filterKYC(){const r=document.getElementById('kycRiskFilter').value,q=document.getElementById('kycSearch').value.toLowerCase();document.querySelectorAll('#kycTable tbody tr').forEach(row=>{row.style.display=(!r||row.dataset.risk===r)&&(!q||row.textContent.toLowerCase().includes(q))?'':'none'})}</script>{% endblock %}
''')

write_file('templates/blacklist.html', r'''{% extends "base.html" %}{% block title %}Blacklist Check{% endblock %}{% block page_title %}Blacklist Check{% endblock %}
{% block content %}<div class="container-fluid">{% if summary %}<div class="row g-3 mb-4">
<div class="col-md-4"><div class="card stat-card border-danger"><div class="card-body text-center"><h2 class="text-danger mb-0">{{ summary.total_hits }}</h2><small class="text-muted">Total Hits</small></div></div></div>
<div class="col-md-4"><div class="card stat-card border-warning"><div class="card-body text-center"><h2 class="text-warning mb-0">{{ summary.txn_hits }}</h2><small class="text-muted">Transaction Hits</small></div></div></div>
<div class="col-md-4"><div class="card stat-card border-info"><div class="card-body text-center"><h2 class="text-info mb-0">{{ summary.merchant_hits }}</h2><small class="text-muted">Merchant Hits</small></div></div></div>
</div>{% endif %}
<div class="card mb-4"><div class="card-body"><div class="row g-2 align-items-center"><div class="col-auto"><select class="form-select form-select-sm" id="blSourceFilter" onchange="filterBL()"><option value="">All</option><option value="Transaction">Transaction</option><option value="Merchant">Merchant</option></select></div><div class="col-auto"><input type="text" class="form-control form-control-sm" id="blSearch" placeholder="Search..." onkeyup="filterBL()"></div><div class="col-auto ms-auto"><button class="btn btn-sm btn-outline-success" onclick="exportTableCSV('blTable','blacklist')"><i class="bi bi-download"></i> Export</button></div></div></div></div>
<div class="card"><div class="card-body table-responsive">{% if results %}<table class="table table-hover table-sm" id="blTable"><thead><tr><th>#</th><th>Severity</th><th>Source</th><th>ID</th><th>Name</th><th>Amount</th><th>Matched On</th><th>Status</th></tr></thead><tbody>{% for r in results %}<tr data-source="{{ r.source }}"><td>{{ loop.index }}</td><td><span class="badge bg-danger">CRITICAL</span></td><td>{% if r.source=='Transaction' %}<i class="bi bi-arrow-left-right text-primary"></i>{% else %}<i class="bi bi-shop text-info"></i>{% endif %} {{ r.source }}</td><td><code>{{ r.id }}</code></td><td>{{ r.name }}</td><td class="text-end">{{ "{:,.0f}".format(r.amount) if r.amount != '-' else '-' }}</td><td class="small text-danger">{{ r.matched_on }}</td><td><span class="badge bg-danger">{{ r.status }}</span></td></tr>{% endfor %}</tbody></table>{% else %}<div class="text-center py-5"><i class="bi bi-shield-check fs-1 text-success"></i><h5 class="mt-3">No Blacklist Matches</h5><a href="{{ url_for('upload') }}" class="btn btn-primary">Upload Data</a></div>{% endif %}</div></div></div>{% endblock %}
{% block extra_js %}<script>function filterBL(){const s=document.getElementById('blSourceFilter').value,q=document.getElementById('blSearch').value.toLowerCase();document.querySelectorAll('#blTable tbody tr').forEach(r=>{r.style.display=(!s||r.dataset.source===s)&&(!q||r.textContent.toLowerCase().includes(q))?'':'none'})}</script>{% endblock %}
''')

print('\n🎉 All files created! Now run:')
print('   pip install -r requirements.txt')
print('   python generate_sample_data.py')
print('   python app.py')
print('   → Open http://localhost:5000')
