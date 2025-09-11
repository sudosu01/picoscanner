import os, re, json, uuid, time, threading, subprocess, platform, shutil
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='.')
CORS(app)

# Platform-specific APKTool command
APKTOOL_CMD = 'apktool.bat' if platform.system() == "Windows" else 'apktool'
ADB_CMD = 'adb'
META_DB_FILE = 'pico_meta_db.json'

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

def run_cmd(cmd, update_fn=None, task_id=None):
    """Run command with real-time output"""
    try:
        if update_fn:
            update_fn(task_id, f"Running: {' '.join(cmd)}")
        
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        for line in proc.stdout:
            if update_fn and line.strip():
                update_fn(task_id, line.strip())
        proc.wait()
        return proc.returncode
    except Exception as e:
        if update_fn:
            update_fn(task_id, f"ERROR: {str(e)}")
        return -1

def detect_device():
    try:
        result = subprocess.run([ADB_CMD, 'devices'], capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            if line.strip() and not line.startswith('List of devices'):
                parts = line.split()
                if len(parts) >= 2 and parts[1] == 'device':
                    return parts[0]
        return None
    except Exception:
        return None

def list_user_packages(adb_target):
    try:
        result = subprocess.run([ADB_CMD, '-s', adb_target, 'shell', 'pm', 'list', 'packages', '-3'],
                               capture_output=True, text=True, timeout=15)
        pkgs = [line.replace('package:', '').strip() for line in result.stdout.splitlines() if line.strip()]
        return [{'index': i+1, 'short': pkg.split('.')[-1], 'package': pkg} for i, pkg in enumerate(pkgs)]
    except Exception:
        return []

def get_apk_paths(adb_target, pkg):
    try:
        result = subprocess.run([ADB_CMD, '-s', adb_target, 'shell', 'pm', 'path', pkg],
                               capture_output=True, text=True, timeout=10)
        return [line.replace('package:', '').strip() for line in result.stdout.splitlines() if line.strip()]
    except Exception:
        return []

def ensure_apk_extension(path):
    return path if path.lower().endswith('.apk') else path + '.apk'

def load_meta_db():
    if not os.path.exists(META_DB_FILE):
        return {}
    try:
        with open(META_DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}

PICO_DB = load_meta_db()

def analyze_decompile(decompile_dir, task_id):
    """Fast analysis with optimized file reading"""
    set_task(task_id, status='running', log_line=f'Starting scan in {decompile_dir}')
    
    results = []
    
    # Process each SDK
    for sdk_name, sdk_conf in PICO_DB.items():
        sdk_result = {
            'sdk': sdk_name,
            'laws': ", ".join(sdk_conf.get('laws', [])),
            'found_inits': [],
            'found_privacy_apis': [],
            'missing_privacy_apis': [],
            'pvp_triggered': []
        }
        
        pvp = set()
        
        # Check initialization patterns
        for init in sdk_conf.get('init', []):
            found = False
            for root, _, files in os.walk(decompile_dir):
                for file in files:
                    if file.endswith((".smali", ".xml", ".java")) or file == "AndroidManifest.xml":
                        file_path = os.path.join(root, file)
                        try:
                            # Fast file reading - just check for presence of token
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                for line in f:
                                    if init in line:
                                        sdk_result['found_inits'].append({'path': file_path, 'line': 'N/A', 'code': 'Found'})
                                        found = True
                                        break
                                    if found:
                                        break
                        except:
                            continue
                if found:
                    break
            if not found:
                sdk_result['missing_privacy_apis'].append(f"init:{init}")
                pvp.add("PVP #1")
        
        # Check privacy APIs
        for law in ("gdpr", "us_p", "coppa"):
            for api in sdk_conf.get(law, []):
                found = False
                for root, _, files in os.walk(decompile_dir):
                    for file in files:
                        if file.endswith((".smali", ".xml", ".java")) or file == "AndroidManifest.xml":
                            file_path = os.path.join(root, file)
                            try:
                                # Fast file reading - just check for presence of token
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    for line in f:
                                        if api in line:
                                            sdk_result['found_privacy_apis'].append({
                                                'law': law, 
                                                'api': api, 
                                                'pos': {'path': file_path, 'line': 'N/A', 'code': 'Found'}
                                            })
                                            found = True
                                            break
                                        if found:
                                            break
                            except:
                                continue
                    if found:
                        break
                if not found:
                    sdk_result['missing_privacy_apis'].append(f"{law}:{api}")
                    pvp.add("PVP #1")
        
        sdk_result['pvp_triggered'] = sorted(list(pvp))
        results.append(sdk_result)
        set_task(task_id, log_line=f'Completed {sdk_name}')
    
    # Save results
    out_path = os.path.join(decompile_dir, "picoscan_results.json")
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    
    set_task(task_id, status='finished', log_line=f'Scan complete: {out_path}', meta={'results': results})

# ---------------- Endpoints ----------------
@app.route('/device')
def endpoint_device():
    return jsonify({'device': detect_device()})

@app.route('/list_apps')
def endpoint_list_apps():
    d = detect_device()
    if not d:
        return jsonify({'error': 'no device'}), 500
    return jsonify({'device': d, 'apps': list_user_packages(d)})

@app.route('/apk_paths')
def endpoint_apk_paths():
    pkg = request.args.get('package')
    d = detect_device()
    if not d:
        return jsonify({'error': 'no device'}), 500
    return jsonify({'device': d, 'package': pkg, 'paths': get_apk_paths(d, pkg)})

@app.route('/start_pull', methods=['POST'])
def start_pull():
    data = request.json
    pkg = data['package']
    apk_path = data['apk_path']
    dest = ensure_apk_extension(data['dest_path'])
    task_id = str(uuid.uuid4())
    TASKS[task_id] = {'status': 'queued', 'logs': [], 'meta': {}}
    
    def worker():
        set_task(task_id, status='running', log_line=f'Pulling {pkg}')
        d = detect_device()
        if not d:
            set_task(task_id, status='error', log_line='No device')
            return
        
        # Ensure destination directory exists
        os.makedirs(os.path.dirname(dest) if os.path.dirname(dest) else '.', exist_ok=True)
        
        rc = run_cmd([ADB_CMD, '-s', d, 'pull', apk_path, dest], set_task, task_id)
        if rc == 0:
            set_task(task_id, status='finished', log_line=f'Pulled to {dest}', meta={'apk': dest})
        else:
            set_task(task_id, status='error', log_line=f'Pull failed with code {rc}')
    
    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'task_id': task_id})

@app.route('/start_decompile', methods=['POST'])
def start_decompile():
    data = request.json
    apk = data['apk_path']
    
    # Validate APK path
    if not apk.lower().endswith('.apk'):
        return jsonify({'error': 'Invalid APK path'}), 400
    
    # Create output directory name based on APK name
    apk_dir = os.path.dirname(apk)
    apk_name = os.path.splitext(os.path.basename(apk))[0]
    out_dir = os.path.join(apk_dir, apk_name)
    
    task_id = str(uuid.uuid4())
    TASKS[task_id] = {'status': 'queued', 'logs': [], 'meta': {}}
    
    def worker():
        set_task(task_id, status='running', log_line=f'Decompiling {apk} to {out_dir}')
        
        # Validate APK exists
        if not os.path.exists(apk):
            set_task(task_id, status='error', log_line=f'APK file not found: {apk}')
            return
        
        # Remove existing directory
        if os.path.exists(out_dir):
            try:
                shutil.rmtree(out_dir)
                set_task(task_id, log_line='Removed existing directory')
            except Exception as e:
                set_task(task_id, status='error', log_line=f'Error removing dir: {str(e)}')
                return
        
        # Build command - use threads for faster decompilation
        cmd = [APKTOOL_CMD, 'd', '-f', '-p', '4', apk, '-o', out_dir]
        
        # Run decompilation
        rc = run_cmd(cmd, set_task, task_id)
        
        if rc == 0 and os.path.exists(out_dir) and os.listdir(out_dir):
            set_task(task_id, status='finished', log_line=f'Decompiled to {out_dir}', 
                    meta={'decompile_dir': out_dir})
        else:
            set_task(task_id, status='error', log_line='Decompilation failed. Check if APKTool is properly installed.')
    
    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'task_id': task_id})

@app.route('/start_scan', methods=['POST'])
def start_scan():
    ddir = request.json['decompile_dir']
    task_id = str(uuid.uuid4())
    TASKS[task_id] = {'status': 'queued', 'logs': [], 'meta': {}}
    threading.Thread(target=analyze_decompile, args=(ddir, task_id), daemon=True).start()
    return jsonify({'task_id': task_id})

@app.route('/open_folder', methods=['POST'])
def open_folder():
    path = request.json.get('path')
    if not path or not os.path.isdir(path):
        return jsonify({'error': 'invalid path'}), 400
    
    try:
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
        return jsonify({'status': 'opened', 'path': path})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/task_status/<task_id>')
def task_status(task_id):
    return jsonify(TASKS.get(task_id, {}))

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, threaded=True)
