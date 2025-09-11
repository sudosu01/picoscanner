# PICO APK Privacy Scanner

This project implements a Privacy-Configurable Scanning System (PICO) to analyze Android APKs for privacy compliance issues. It leverages a structured database of SDKs (PICO MetaDB) that maps APIs to legal frameworks (GDPR, CCPA, COPPA, etc.) and checks for Policy Violation Principles (PVPs) in decompiled APKs.

# Tools Required
* Nox Player (or any Android emulator / real device) - Used to run apps and pull APKs via ADB.
* ADB (Android Debug Bridge) - To connect with emulator/device and pull APK files.
* apktool - For decompiling APK files into smali and XML files.
* Python 3.9+ - For running the scanner.
Dependencies: pip install tabulate

# Setup (Manual flow)
- Decompile APK with apktool
apktool d app.apk -o app_decompiled -f

- Save your structured SDK rules as pico_meta_db.json in the project directory.
- Save scanner script as scan_decompile.py (provided in this repo).

# Usage
- Run the scanner:
python scan_decompile.py

- Enter the decompiled APK folder path when prompted:
Enter path to decompiled APK folder: /path/to/app_decompiled

- Traverse all files (AndroidManifest.xml, .smali, .xml, .java).
Match against PICO DB entries, Identify found/missing APIs, Map issues to PVP violations.

# Output:
An HTML report (scan_report.html) with a table view

#
#

# Automated Flow (Web Server + UI)
Instead of decompiling manually and running the scanner yourself, this version provides a web dashboard where everything is automated:
- Connect to emulator/device via ADB
- Pull APKs directly from device
- Decompile them with apktool
- Scan against PICO MetaDB
- Show results in browser with logs and HTML tables

# Tools Required
- Same as manual flow (Nox Player, ADB, apktool, Python 3.9+)
- Flask – backend web server
- Celery + Redis – optional, for handling long-running tasks asynchronously
- Flask-CORS – to allow browser access
Dependencies: pip install flask flask-cors

# Setup (Automated flow)
- Start the Flask server: python server.py
- Open the UI
Open http://127.0.0.1:5000 in your browser.

# Workflow in the UI
- Select an app from the device
- Choose an APK split
- Enter destination path and pull
- Decompile (automatically starts once pull finishes)
- Scan (runs automatically after decompile)
- View results in the results panel

# Output (Automated Flow)
- The browser interface shows Logs panel of the puull, decompile and scanned android file
- Results panel displays output in structured compliance table and also save output in json in the decompiled folder:
| SDK | Laws | Metadata | Found APIs | Missing APIs | PVPs Triggered |

# Screenshots
