# PICO APK Privacy Scanner

This project implements a Privacy-Configurable Scanning System (PICO) to analyze Android APKs for privacy compliance issues. It leverages a structured database of SDKs (PICO MetaDB) that maps APIs to legal frameworks (GDPR, CCPA, COPPA, etc.) and checks for Policy Violation Principles (PVPs) in decompiled APKs.

# Algorithm
Step 1: Initialization
-	Connect to Android device/emulator via ADB.
-	Pull the target APK to local storage.
-	Load PICO DB into memory.
*** Ensures the environment is set up and the knowledge base (PICO DB) is ready for pattern matching.

Step 2: Decomplication
-	Install Apktool to decompile the APK into smali code + resources.
-	Store the decompiled directory for analysis.
**** For the static analysis, this requires source like files (smali) rather than raw binaries.

Step 3: File Preprocessing
-	Traverse all decompiled files (.smali, AndroidManifest.xml, config files).
-	Convert file content into searchable text (UTF-8 strings + extracted ASCII).
**** Normalizing the file content to allow the PICO DB to match patterns across pattern scanning works across multiple file types.

Step 4: SDK Signature Matching (PICO DB)
-	Retrieve defined API patterns (functions, classes, init calls).
-	Search across the decompiled text corpus.
**** For the SDK APIs found and matched, return signatures detected with the PICO DB and for Missing APIs, return expected but absent.

Step 5: Compliance Evaluation (PICO DB)
-	For each SDK with matches with the PICO DB, retrieve with associated laws (GDPR, COPPA, CCPA, etc.).
-	Check for metadata rules (consent checks, opt-out APIs).
-	Identify Policy Violation Points (PVPs) when APIs are misused or missing.
**** Links technical patterns to real compliance concerns on the PICO DB.

Step 6: Report Generation
-	Aggregate results into structured JSON by providing auditors and developers with a clear, actionable privacy compliance report.


# Flowchart of Privacy Scanning Process
<img width="768" height="726" alt="image" src="https://github.com/user-attachments/assets/b758965c-b563-434e-9af7-4bfdf9e77308" />

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

- Emulator/UI Scanner
<img width="1366" height="635" alt="sd" src="https://github.com/user-attachments/assets/1864d4ce-d644-4228-ba62-065a5318bdbc" />


- Decompiled file
<img width="807" height="413" alt="image" src="https://github.com/user-attachments/assets/5c12bfe1-9ee1-4db8-8aa4-42c20703bafd" />

- 
