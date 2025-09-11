import os
import re
import json
import uuid
import time
import threading
import subprocess
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.')
CORS(app)

# Configuration
ADB_CMD = os.environ.get('ADB_CMD', 'adb')
APKTOOL_CMD = os.environ.get('APKTOOL_CMD', 'apktool')  # use apktool on PATH or set env var
META_DB_FILE = os.path.join(os.path.dirname(__file__), 'pico_meta_db.json')

# In-memory task store
TASKS = {}

# ---------------------------
# Utility / task infrastructure
# ---------------------------
def set_task(task_id, status=None, log_line=None, meta=None):
    if task_id not in TASKS:
        TASKS[task_id] = {'status': 'idle', 'logs': [], 'meta': {}}
    if status:
        TASKS[task_id]['status'] = status
    if log_line:
        TASKS[task_id]['logs'].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {log_line}")
    if meta:
        TASKS[task_id]['meta'].update(meta)

def run_cmd(cmd, cwd=None, update_fn=None, task_id=None):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=cwd, text=True, bufsize=1)
    for line in proc.stdout:
        ln = line.rstrip()
        if update_fn:
            update_fn(task_id, ln)
    proc.wait()
    return proc.returncode

def detect_device():
    try:
        p = subprocess.run([ADB_CMD, 'devices'], capture_output=True, text=True)
        for line in p.stdout.splitlines():
            s = line.strip()
            if not s or s.startswith('List of devices'):
                continue
            parts = s.split()
            if len(parts) >= 2 and parts[1] == 'device':
                return parts[0]
        return None
    except Exception:
        return None

def list_user_packages(adb_target):
    p = subprocess.run([ADB_CMD, '-s', adb_target, 'shell', 'pm', 'list', 'packages', '-3'], capture_output=True, text=True)
    lines = [l.replace('package:','').strip() for l in p.stdout.splitlines() if l.strip()]
    out = []
    for i, pkg in enumerate(lines, start=1):
        short = pkg.split('.')[-1]
        out.append({'index': i, 'short': short, 'package': pkg})
    return out

def get_apk_paths(adb_target, pkg):
    p = subprocess.run([ADB_CMD, '-s', adb_target, 'shell', 'pm', 'path', pkg], capture_output=True, text=True)
    paths = [l.replace('package:','').strip() for l in p.stdout.splitlines() if l.strip()]
    return paths

def ensure_apk_extension(path):
    if not path.lower().endswith('.apk'):
        return path + '.apk'
    return path

# ---------------------------
# Load PICO meta DB
# ---------------------------
def load_meta_db():
    if not os.path.exists(META_DB_FILE):
        return {}
    try:
        with open(META_DB_FILE, 'r', encoding='utf-8') as fh:
            return json.load(fh)
    except Exception:
        try:
            # try tolerant load
            with open(META_DB_FILE, 'r', encoding='utf-8', errors='ignore') as fh:
                return json.load(fh)
        except Exception:
            return {}

PICO_DB = load_meta_db()

# ---------------------------
# File utilities for scanning
# ---------------------------
def file_to_text(path, max_bytes=2000000):
    try:
        with open(path, 'r', encoding='utf-8', errors='strict') as f:
            return f.read()
    except Exception:
        try:
            with open(path, 'r', encoding='latin-1', errors='ignore') as f:
                return f.read()
        except Exception:
            try:
                with open(path, 'rb') as f:
                    b = f.read(max_bytes)
                    # extract ascii-like sequences
                    strs = re.findall(rb'[\x20-\x7E]{4,}', b)
                    return '\n'.join([s.decode('ascii', errors='ignore') for s in strs])
            except Exception:
                return ''

def build_search_corpus(decompile_dir):
    corpus = []  # list of (path, text, line_indexed list)
    for root, _, files in os.walk(decompile_dir):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                txt = file_to_text(fp)
                lines = txt.splitlines()
                corpus.append({'path': fp, 'text': txt, 'lines': lines})
            except Exception:
                continue
    return corpus

# Simple heuristic: find first occurrence (file, line index) of a token
def find_token_positions(corpus, token):
    results = []
    pat = re.escape(token)
    regex = re.compile(pat)
    for entry in corpus:
        for i, line in enumerate(entry['lines']):
            if regex.search(line):
                results.append({'path': entry['path'], 'line_index': i, 'line': line})
                break
    return results

# Heuristic to search near a location for argument tokens/values (search N lines around)
def search_nearby_for_values(entry_lines, idx, values, window=6):
    found = {}
    low = max(0, idx - window)
    high = min(len(entry_lines)-1, idx + window)
    chunk = '\n'.join(entry_lines[low:high+1])
    for k, v in values.items():
        # v might be basic (true/false) or string; convert to string tokens to search
        sval = str(v)
        if not sval or sval == 'null':
            continue
        if sval in chunk or re.search(re.escape(sval), chunk):
            found[k] = True
        else:
            found[k] = False
    return found

# ---------------------------
# Scanning algorithm (robust heuristics)
# ---------------------------
def analyze_decompile(decompile_dir, task_id):
    set_task(task_id, status='running', log_line=f'Starting scan in {decompile_dir}')
    if not os.path.isdir(decompile_dir):
        set_task(task_id, status='error', log_line='Decompile directory not found')
        return

    corpus = build_search_corpus(decompile_dir)
    if not corpus:
        set_task(task_id, status='warning', log_line='No searchable files found in decompile dir')

    results = []

    # For each SDK entry in PICO_DB, run checks
    for sdk_name, sdk_conf in PICO_DB.items():
        sdk_result = {
            'sdk': sdk_name,
            'found_init': [],
            'found_privacy_apis': [],
            'missing_privacy_apis': [],
            'pvp_triggered': [],
            'notes': []
        }

        # 1) Check init signatures
        init_entries = sdk_conf.get('init', [])
        init_positions = []
        for init_e in init_entries:
            # some entries might be strings or objects
            if isinstance(init_e, dict):
                clazz = init_e.get('apiClazzName') or ''
                method = init_e.get('apiMethodName') or ''
            else:
                # fallback: if string, search for it
                clazz = str(init_e)
                method = ''
            token = clazz if clazz else (f"{clazz}.{method}" if method else clazz)
            if token:
                positions = find_token_positions(corpus, clazz) if clazz else []
                if positions:
                    sdk_result['found_init'].extend(positions)
                    init_positions.extend(positions)
        # 2) privacy APIs per law (gdpr, us_p, coppa)
        pvp_local = set()
        for law_key in ('gdpr','us_p','coppa'):
            entries = sdk_conf.get(law_key, [])
            for ent in entries:
                if isinstance(ent, str):
                    # e.g. "IAB Framework" or similar
                    # record as note that this SDK references a framework (not direct API)
                    sdk_result['notes'].append(f"{law_key}: {ent}")
                    continue
                if not isinstance(ent, dict):
                    continue
                clazz = ent.get('apiClazzName') or ''
                method = ent.get('apiMethodName') or ''
                consent_index = ent.get('consentArgsIndex')
                consent_values = ent.get('consentArgsValue') or {}
                policy_args = ent.get('policyArgs') or {}

                # find token occurrences - prefer matching both class & method if possible
                token_candidates = []
                if clazz and method:
                    token_candidates.append(f"{clazz}.{method}")
                    token_candidates.append(method)
                    token_candidates.append(clazz)
                elif clazz:
                    token_candidates.append(clazz)
                elif method:
                    token_candidates.append(method)

                found_any = False
                found_positions = []
                for token in token_candidates:
                    if not token:
                        continue
                    positions = find_token_positions(corpus, token)
                    if positions:
                        found_any = True
                        found_positions.extend(positions)

                if found_any:
                    sdk_result['found_privacy_apis'].append({
                        'law': law_key,
                        'clazz': clazz,
                        'method': method,
                        'positions': found_positions
                    })
                    # attempt a nearby value/arg heuristic on the first occurrence
                    pos = found_positions[0]
                    # find the corpus entry containing this path
                    entry = next((c for c in corpus if c['path'] == pos['path']), None)
                    if entry and consent_values:
                        nearby = search_nearby_for_values(entry['lines'], pos['line_index'], consent_values)
                        # if none of consent_values matched, mark as potential PVP
                        if not any(nearby.get(k) for k in nearby):
                            pvp_local.add('PVP #2')  # wrong/invalid semantics or not explicit
                            sdk_result['notes'].append(f"{law_key}: consent args presence not detected near {pos['path']}:{pos['line_index']}")
                    # if policy_args specified, check those keys appear near
                    if policy_args:
                        # policy_args is mapping e.g. {"0":"GDPR"}; search for value strings
                        for _, val in policy_args.items():
                            entry = entry or (next((c for c in corpus if c['path'] == pos['path']), None))
                            if entry and val and val not in '\n'.join(entry['lines'][max(0,pos['line_index']-6):pos['line_index']+6]):
                                pvp_local.add('PVP #5')
                else:
                    # not found - missing privacy API for that law
                    sdk_result['missing_privacy_apis'].append({
                        'law': law_key,
                        'clazz': clazz,
                        'method': method
                    })
                    pvp_local.add('PVP #1')  # missing config

        # 3) Heuristic invocation order: if init found and privacy API found, check which appears first
        if init_positions and sdk_result['found_privacy_apis']:
            try:
                init_first = min([p['line_index'] for p in init_positions])
                privacy_first = min([p['positions'][0]['line_index'] for p in sdk_result['found_privacy_apis'] if p['positions']])
                if init_first < privacy_first:
                    # init occurs before privacy config -> possible order violation
                    pvp_local.add('PVP #3')
                    sdk_result['notes'].append('Init appears before privacy configuration in scanned files (possible order issue)')
            except Exception:
                pass
        elif init_positions and not sdk_result['found_privacy_apis']:
            # init exists but no privacy APIs -> missing config
            pvp_local.add('PVP #1')

        # 4) Default / privacy by default heuristic: simple check for presence of obvious enable flags
        # (search for 'set*Enabled', 'startTracking', 'setAnalyticsCollectionEnabled', etc.)
        default_risks = []
        default_patterns = [r'setAnalyticsCollectionEnabled', r'startTracking', r'send.*analytics', r'.*enable.*tracking']
        combined_text = '\n'.join([c['text'] for c in corpus])
        for pat in default_patterns:
            if re.search(pat, combined_text, re.IGNORECASE):
                default_risks.append(pat)
        if default_risks:
            sdk_result['notes'].append('Found potential analytics/tracking enable patterns; review defaults')
            pvp_local.add('PVP #4')

        # finalize pvp list
        sdk_result['pvp_triggered'] = sorted(list(pvp_local))
        results.append(sdk_result)

    # write results file to decompile dir
    out_path = os.path.join(decompile_dir, 'picoscan_results.json')
    try:
        with open(out_path, 'w', encoding='utf-8') as fh:
            json.dump(results, fh, indent=2)
    except Exception as e:
        set_task(task_id, status='error', log_line=f'Failed to write results: {e}')
        return

    set_task(task_id, status='finished', log_line=f'Scan complete, results saved to {out_path}', meta={'results_path': out_path, 'results': results})

# ---------------------------
# Task wrappers (pull/decompile/scan)
# ---------------------------
@app.route('/device', methods=['GET'])
def endpoint_device():
    d = detect_device()
    return jsonify({'device': d})

@app.route('/list_apps', methods=['GET'])
def endpoint_list_apps():
    d = detect_device()
    if not d:
        return jsonify({'error': 'no device'}), 500
    apps = list_user_packages(d)
    return jsonify({'device': d, 'apps': apps})

@app.route('/apk_paths', methods=['GET'])
def endpoint_apk_paths():
    pkg = request.args.get('package')
    d = detect_device()
    if not d:
        return jsonify({'error': 'no device'}), 500
    paths = get_apk_paths(d, pkg)
    return jsonify({'device': d, 'package': pkg, 'paths': paths})

@app.route('/start_pull', methods=['POST'])
def start_pull():
    data = request.json
    pkg = data.get('package')
    apk_path = data.get('apk_path')
    dest = data.get('dest_path')
    task_id = str(uuid.uuid4())
    TASKS[task_id] = {'status': 'queued', 'logs': [], 'meta': {'package': pkg, 'apk_path': apk_path, 'dest_path': dest}}
    thread = threading.Thread(target=task_pull, args=(task_id,))
    thread.daemon = True
    thread.start()
    return jsonify({'task_id': task_id})

def task_pull(task_id):
    meta = TASKS[task_id]['meta']
    set_task(task_id, status='running', log_line='Starting pull')
    d = detect_device()
    if not d:
        set_task(task_id, status='error', log_line='No device found')
        return
    dest = ensure_apk_extension(meta.get('dest_path') or f"./{meta.get('package')}.apk")
    apk_remote = meta.get('apk_path')
    set_task(task_id, log_line=f'Pulling {apk_remote} to {dest}')
    try:
        rc = run_cmd([ADB_CMD, '-s', d, 'pull', apk_remote, dest], update_fn=set_task, task_id=task_id)
    except Exception as e:
        set_task(task_id, status='error', log_line=str(e))
        return
    if rc == 0:
        set_task(task_id, status='finished', log_line='Pull finished', meta={'local_apk': os.path.abspath(dest)})
    else:
        set_task(task_id, status='error', log_line=f'Pull failed rc={rc}')

@app.route('/start_decompile', methods=['POST'])
def start_decompile():
    data = request.json
    apk = data.get('apk_path')
    fast = data.get('fast', True)  # default to skip resources for speed
    task_id = str(uuid.uuid4())
    TASKS[task_id] = {'status': 'queued', 'logs': [], 'meta': {'apk': apk, 'fast': fast}}
    thread = threading.Thread(target=task_decompile_and_scan, args=(task_id,))
    thread.daemon = True
    thread.start()
    return jsonify({'task_id': task_id})

def task_decompile_and_scan(task_id):
    meta = TASKS[task_id]['meta']
    apk = meta.get('apk')
    fast = meta.get('fast', True)
    if not apk or not os.path.isfile(apk):
        set_task(task_id, status='error', log_line=f'APK not found: {apk}')
        return
    out_dir = os.path.join(os.path.dirname(apk), os.path.splitext(os.path.basename(apk))[0] + '_decompile')
    set_task(task_id, status='running', log_line=f'Starting decompile to {out_dir}')
    cmd = [APKTOOL_CMD, 'd', apk, '-f', '-o', out_dir]
    if fast:
        # -s skip resources (apktool option)
        cmd.insert(2, '-s')
    rc = run_cmd(cmd, update_fn=set_task, task_id=task_id)
    if rc == 0:
        set_task(task_id, log_line=f'Decompiled to {out_dir}', meta={'decompile_dir': out_dir})
        # kick off scan
        scan_task_id = str(uuid.uuid4())
        TASKS[scan_task_id] = {'status': 'queued', 'logs': [], 'meta': {'decompile_dir': out_dir}}
        t = threading.Thread(target=analyze_decompile, args=(out_dir, scan_task_id))
        t.daemon = True
        t.start()
        set_task(task_id, status='finished', log_line=f'Auto-started scan task {scan_task_id}', meta={'scan_task_id': scan_task_id})
    else:
        set_task(task_id, status='error', log_line=f'Decompile failed rc={rc}')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    ddir = data.get('decompile_dir')
    task_id = str(uuid.uuid4())
    TASKS[task_id] = {'status': 'queued', 'logs': [], 'meta': {'decompile_dir': ddir}}
    thread = threading.Thread(target=analyze_decompile, args=(ddir, task_id))
    thread.daemon = True
    thread.start()
    return jsonify({'task_id': task_id})

@app.route('/task_status/<task_id>', methods=['GET'])
def task_status(task_id):
    t = TASKS.get(task_id, {})
    return jsonify(t)

@app.route('/results/<path:filename>', methods=['GET'])
def download_file(filename):
    return send_from_directory('.', filename, as_attachment=True)

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
