import os, re, json, uuid, time, threading, subprocess, platform, shutil
import tempfile, glob, fnmatch, traceback
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from pathlib import Path

app = Flask(__name__, static_folder='.')
CORS(app)

# Platform-specific commands
APKTOOL_CMD = 'apktool.bat' if platform.system() == "Windows" else 'apktool'
ADB_CMD = 'adb'
META_DB_FILE = 'pico_meta_db.json'

TASKS = {}

# ---------------- Enhanced Utility Functions ----------------
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
    """Detect connected Android devices, including Nox Player instances"""
    try:
        # First try regular devices
        result = subprocess.run([ADB_CMD, 'devices'], capture_output=True, text=True, timeout=10)
        devices = []
        
        for line in result.stdout.splitlines():
            if line.strip() and not line.startswith('List of devices'):
                parts = line.split()
                if len(parts) >= 2 and parts[1] == 'device':
                    devices.append(parts[0])
        
        # Try to detect Nox Player instances
        try:
            if platform.system() == "Windows":
                # Check for Nox Player default ADB port
                nox_result = subprocess.run([ADB_CMD, 'connect', '127.0.0.1:62001'], 
                                          capture_output=True, text=True, timeout=5)
                if 'connected' in nox_result.stdout:
                    devices.append('127.0.0.1:62001')
        except:
            pass
            
        return devices
    except Exception:
        return []

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
        # Try to download from the provided URL or use a default
        try:
            import requests
            response = requests.get('https://sites.google.com/view/picoscan/metadb', timeout=10)
            if response.status_code == 200:
                with open(META_DB_FILE, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                return json.loads(response.text)
        except:
            pass
        
        # Return empty DB if download fails
        return {}
    
    try:
        with open(META_DB_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading PICO DB: {e}")
        return {}

PICO_DB = load_meta_db()

def is_text_file(file_path):
    """Check if a file is likely to be a text file"""
    text_extensions = {'.smali', '.java', '.xml', '.json', '.txt', '.html', '.js', '.css', '.kt'}
    return os.path.splitext(file_path)[1].lower() in text_extensions

def read_file_content(file_path):
    """Read file content with various encodings and error handling - only for text files"""
    # Skip binary files
    if not is_text_file(file_path):
        return ""
    
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                content = f.read()
                return content, True
        except UnicodeDecodeError:
            continue
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
    
    # If all encodings fail, try binary read
    try:
        with open(file_path, 'rb') as f:
            content = f.read().decode('utf-8', errors='ignore')
            return content, False
    except Exception as e:
        print(f"Binary read failed for {file_path}: {e}")
        return "", False

def analyze_file_content(content, file_path, sdk_conf):
    """Analyze file content for PICO patterns - fixed to handle string content only"""
    findings = {
        'found_inits': [],
        'found_privacy_apis': []
    }
    
    # Ensure content is a string
    if not isinstance(content, str):
        return findings
    
    # Check initialization patterns
    for init in sdk_conf.get('init', []):
        if isinstance(init, str) and init in content:
            # Get exact line numbers and context
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                if init in line:
                    start = max(0, line_num-3)
                    end = min(len(lines), line_num+2)
                    context = '\n'.join([f"{i}: {line}" for i, line in enumerate(lines[start:end], start+1)])
                    
                    findings['found_inits'].append({
                        'path': file_path,
                        'line': line_num,
                        'code': context,
                        'pattern': init,
                        'exact_match': line.strip()
                    })
    
    # Check privacy APIs
    for law in ("gdpr", "us_p", "coppa"):
        for api in sdk_conf.get(law, []):
            if isinstance(api, str) and api in content:
                # Get exact line numbers and context
                lines = content.split('\n')
                for line_num, line in enumerate(lines, 1):
                    if api in line:
                        start = max(0, line_num-3)
                        end = min(len(lines), line_num+2)
                        context = '\n'.join([f"{i}: {line}" for i, line in enumerate(lines[start:end], start+1)])
                        
                        findings['found_privacy_apis'].append({
                            'law': law,
                            'api': api,
                            'path': file_path,
                            'line': line_num,
                            'code': context,
                            'exact_match': line.strip()
                        })
    
    return findings

def analyze_decompile(decompile_dir, task_id):
    """Enhanced analysis with deep file reading and real-time updates - fixed to skip binary files"""
    set_task(task_id, status='running', log_line=f'Starting deep scan in {decompile_dir}')
    
    results = []
    total_files = 0
    processed_files = 0
    
    # Count all text files for progress estimation (excluding our own report files)
    for root, _, files in os.walk(decompile_dir):
        for file in files:
            if is_text_file(file) and not file.endswith('_results.json'):
                total_files += 1
    
    # Process each SDK with real-time updates
    for sdk_name, sdk_conf in PICO_DB.items():
        sdk_result = {
            'sdk': sdk_name,
            'laws': ", ".join(sdk_conf.get('laws', [])),
            'found_inits': [],
            'found_privacy_apis': [],
            'missing_privacy_apis': [],
            'pvp_triggered': [],
            'scanned_files': 0
        }
        
        pvp = set()
        
        # Walk through all files in the decompiled directory
        for root, _, files in os.walk(decompile_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, decompile_dir)
                
                # Skip binary files and our own report files
                if not is_text_file(file_path) or file.endswith('_results.json'):
                    continue
                    
                try:
                    # Read file content with robust encoding handling
                    content, is_proper_text = read_file_content(file_path)
                    
                    if content:
                        # Analyze content for this SDK's patterns
                        file_findings = analyze_file_content(content, rel_path, sdk_conf)
                        
                        # Send immediate notification about findings
                        for finding in file_findings['found_inits']:
                            set_task(task_id, log_line=f"FOUND INIT in {rel_path}:{finding['line']} - {finding['pattern']}")
                        
                        for finding in file_findings['found_privacy_apis']:
                            set_task(task_id, log_line=f"FOUND {finding['law'].upper()} API in {rel_path}:{finding['line']} - {finding['api']}")
                        
                        sdk_result['found_inits'].extend(file_findings['found_inits'])
                        sdk_result['found_privacy_apis'].extend(file_findings['found_privacy_apis'])
                    
                    processed_files += 1
                    sdk_result['scanned_files'] += 1
                    
                    # Update progress every 10 files or 1 second
                    if processed_files % 10 == 0 or time.time() % 1 < 0.1:
                        progress = (processed_files / total_files) * 100
                        
                        # Send partial results for real-time display
                        partial_results = results + [sdk_result]
                        set_task(task_id, meta={
                            'progress': progress, 
                            'partial_results': partial_results,
                            'current_file': rel_path,
                            'recent_findings': file_findings  # Add recent findings for live display
                        })
                        
                except Exception as e:
                    set_task(task_id, log_line=f"Error processing {rel_path}: {str(e)}")
                    continue
        
        # Check for missing privacy APIs
        for law in ("gdpr", "us_p", "coppa"):
            for api in sdk_conf.get(law, []):
                found = any(api in finding['api'] for finding in sdk_result['found_privacy_apis'])
                if not found:
                    sdk_result['missing_privacy_apis'].append(f"{law}:{api}")
                    pvp.add("PVP #1")
        
        # Check for missing initialization patterns
        for init in sdk_conf.get('init', []):
            found = any(init in finding['pattern'] for finding in sdk_result['found_inits'])
            if not found:
                sdk_result['missing_privacy_apis'].append(f"init:{init}")
                pvp.add("PVP #1")
        
        sdk_result['pvp_triggered'] = sorted(list(pvp))
        results.append(sdk_result)
        
        # Update with completed SDK results
        set_task(task_id, log_line=f'Completed {sdk_name}', meta={
            'progress': (processed_files / total_files) * 100, 
            'partial_results': results,
            'current_file': f"Completed {sdk_name}"
        })
    
    # Save detailed results
    out_path = os.path.join(decompile_dir, "picoscan_detailed_results.json")
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Generate summary
    summary = {
        'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_files_scanned': total_files,
        'total_sdks_analyzed': len(results),
        'total_findings': sum(len(r['found_inits']) + len(r['found_privacy_apis']) for r in results),
        'total_pvps': sum(len(r['pvp_triggered']) for r in results),
        'detailed_results_path': out_path
    }
    
    summary_path = os.path.join(decompile_dir, "picoscan_summary.json")
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    
    set_task(task_id, status='finished', log_line=f'Scan complete. Results: {out_path}', 
             meta={'results': results, 'progress': 100, 'summary': summary})

# ---------------- Flask Endpoints ----------------
@app.route('/device')
def endpoint_device():
    return jsonify({'device': detect_device()})

@app.route('/list_apps')
def endpoint_list_apps():
    d = detect_device()
    if not d:
        return jsonify({'error': 'no device'}), 500
    apps = list_user_packages(d[0] if d else '')
    return jsonify({'device': d, 'apps': apps})

@app.route('/apk_paths')
def endpoint_apk_paths():
    pkg = request.args.get('package')
    d = detect_device()
    if not d:
        return jsonify({'error': 'no device'}), 500
    return jsonify({'device': d, 'package': pkg, 'paths': get_apk_paths(d[0], pkg)})

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
        
        rc = run_cmd([ADB_CMD, '-s', d[0], 'pull', apk_path, dest], set_task, task_id)
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
    data = request.json
    ddir = data['decompile_dir']
    task_id = str(uuid.uuid4())
    TASKS[task_id] = {'status': 'queued', 'logs': [], 'meta': {}}
    threading.Thread(target=analyze_decompile, args=(ddir, task_id), daemon=True).start()
    return jsonify({'task_id': task_id})

@app.route('/browse_folder')
def browse_folder():
    path = request.args.get('path', '.')
    try:
        # Convert to absolute path for safety
        abs_path = os.path.abspath(path)
        
        # Check if path exists
        if not os.path.exists(abs_path):
            return jsonify({'error': f'Path does not exist: {abs_path}'}), 404
            
        items = []
        for item in os.listdir(abs_path):
            item_path = os.path.join(abs_path, item)
            items.append({
                'name': item,
                'path': item_path,
                'is_dir': os.path.isdir(item_path),
                'size': os.path.getsize(item_path) if os.path.isfile(item_path) else 0
            })
        return jsonify({'path': abs_path, 'items': items})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
    app.run(host='0.0.0.0', port=5000, threaded=True, debug=True)
