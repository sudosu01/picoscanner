import os, re, json, uuid, time, threading, subprocess
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.')
CORS(app)

ADB_CMD = os.environ.get('ADB_CMD', 'adb')
APKTOOL_CMD = os.environ.get('APKTOOL_CMD', 'apktool')
META_DB_FILE = os.path.join(os.path.dirname(__file__), 'pico_meta_db.json')

TASKS = {}

# ---------------- Utility ----------------
def set_task(task_id, status=None, log_line=None, meta=None):
    if task_id not in TASKS:
        TASKS[task_id] = {'status': 'idle', 'logs': [], 'meta': {}}
    if status:
        TASKS[task_id]['status'] = status
    if log_line:
        TASKS[task_id]['logs'].append(f"{time.strftime('%H:%M:%S')} {log_line}")
    if meta:
        TASKS[task_id]['meta'].update(meta)

def run_cmd(cmd, cwd=None, update_fn=None, task_id=None):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            cwd=cwd, text=True, bufsize=1)
    for line in proc.stdout:
        if update_fn:
            update_fn(task_id, line.rstrip())
    proc.wait()
    return proc.returncode

def detect_device():
    try:
        p = subprocess.run([ADB_CMD, 'devices'], capture_output=True, text=True)
        for line in p.stdout.splitlines():
            if line.strip() and not line.startswith('List of devices'):
                parts = line.split()
                if len(parts) >= 2 and parts[1] == 'device':
                    return parts[0]
        return None
    except Exception:
        return None

def ensure_apk_extension(path):
    return path if path.lower().endswith('.apk') else path + '.apk'

def load_meta_db():
    if not os.path.exists(META_DB_FILE):
        return {}
    with open(META_DB_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

PICO_DB = load_meta_db()

# ---------------- File Scan ----------------
def file_to_text(path, max_bytes=2000000):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        try:
            with open(path, 'rb') as f:
                return f.read(max_bytes).decode('latin-1', errors='ignore')
        except:
            return ''

def build_search_corpus(decompile_dir):
    corpus = []
    for root, _, files in os.walk(decompile_dir):
        for fn in files:
            if fn.endswith((".smali", ".xml", ".java", ".txt")) or fn == "AndroidManifest.xml":
                fp = os.path.join(root, fn)
                txt = file_to_text(fp)
                if txt:
                    corpus.append({'path': fp, 'lines': txt.splitlines()})
    return corpus

def find_token_positions(corpus, token):
    results = []
    pat = re.escape(token)
    regex = re.compile(pat)
    for entry in corpus:
        for i, line in enumerate(entry['lines']):
            if regex.search(line):
                results.append({'path': entry['path'], 'line': i+1, 'code': line.strip()})
                break
    return results

def analyze_decompile(decompile_dir, task_id):
    set_task(task_id, status='running', log_line=f'Starting scan in {decompile_dir}')
    corpus = build_search_corpus(decompile_dir)
    results = []
    for sdk_name, sdk_conf in PICO_DB.items():
        sdk_result = {
            'sdk': sdk_name,
            'laws': ", ".join(sdk_conf.get('laws', [])),
            'found_inits': [],
            'found_privacy_apis': [],
            'missing_privacy_apis': [],
            'pvp_triggered': []
        }
        pvp_local = set()
        for init in sdk_conf.get('init', []):
            pos = find_token_positions(corpus, init)
            if pos: sdk_result['found_inits'].extend(pos)
            else:
                sdk_result['missing_privacy_apis'].append(f"init:{init}")
                pvp_local.add("PVP #1")
        for law in ("gdpr","us_p","coppa"):
            for api in sdk_conf.get(law, []):
                pos = find_token_positions(corpus, api)
                if pos: sdk_result['found_privacy_apis'].extend([{'law':law,'api':api,'pos':p} for p in pos])
                else:
                    sdk_result['missing_privacy_apis'].append(f"{law}:{api}")
                    pvp_local.add("PVP #1")
        sdk_result['pvp_triggered'] = sorted(list(pvp_local))
        results.append(sdk_result)
    out_path = os.path.join(decompile_dir, "picoscan_results.json")
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    set_task(task_id, status='finished', log_line=f'Scan complete: {out_path}', meta={'results': results})

# ---------------- Tasks ----------------
@app.route('/start_pull', methods=['POST'])
def start_pull():
    data = request.json
    pkg = data.get('package')
    apk_path = data.get('apk_path')
    dest = ensure_apk_extension(data.get('dest_path'))
    task_id = str(uuid.uuid4())
    TASKS[task_id] = {'status':'queued','logs':[],'meta':{}}
    def worker():
        set_task(task_id, status='running', log_line=f'Pulling {pkg}')
        d = detect_device()
        if not d:
            set_task(task_id, status='error', log_line='No device')
            return
        rc = run_cmd([ADB_CMD,'-s',d,'pull',apk_path,dest], update_fn=set_task, task_id=task_id)
        if rc==0:
            set_task(task_id, status='finished', log_line=f'Pulled to {dest}', meta={'apk':dest})
        else:
            set_task(task_id, status='error', log_line=f'Failed rc={rc}')
    threading.Thread(target=worker,daemon=True).start()
    return jsonify({'task_id':task_id})

@app.route('/start_decompile', methods=['POST'])
def start_decompile():
    data = request.json
    apk = data.get('apk_path')
    out_dir = os.path.splitext(apk)[0]+'_decompile'
    task_id = str(uuid.uuid4())
    TASKS[task_id] = {'status':'queued','logs':[],'meta':{}}
    def worker():
        set_task(task_id, status='running', log_line=f'Decompiling {apk}')
        cmd = [APKTOOL_CMD,'d','-f','-s',apk,'-o',out_dir]
        rc = run_cmd(cmd, update_fn=set_task, task_id=task_id)
        if rc==0:
            set_task(task_id, status='finished', log_line=f'Decompiled to {out_dir}', meta={'decompile_dir':out_dir})
        else:
            set_task(task_id, status='error', log_line=f'Decompile failed rc={rc}')
    threading.Thread(target=worker,daemon=True).start()
    return jsonify({'task_id':task_id})

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    ddir = data.get('decompile_dir')
    task_id = str(uuid.uuid4())
    TASKS[task_id] = {'status':'queued','logs':[],'meta':{}}
    threading.Thread(target=analyze_decompile,args=(ddir,task_id),daemon=True).start()
    return jsonify({'task_id':task_id})

@app.route('/task_status/<task_id>', methods=['GET'])
def task_status(task_id):
    return jsonify(TASKS.get(task_id, {}))

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

if __name__=='__main__':
    app.run(host='0.0.0.0',port=5000)
