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
