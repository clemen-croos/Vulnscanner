## Main Features

VulnScanner is a full-stack Android APK security scanner that supports both static and dynamic security analysis.

- Upload Android APK files through the website or mobile application
- Enable static analysis, dynamic analysis or both
- Run static analysis before dynamic analysis when both are selected
- Inspect Android manifests, permissions, application code and resources
- Detect hardcoded credentials, weak cryptography and insecure WebViews
- Identify insecure storage and network configurations
- Inspect native libraries, certificates and third-party SDKs
- Use entropy and context-based filtering to reduce false positives
- Install and test APKs on a dedicated Android emulator
- Monitor runtime logs, storage, debugging interfaces and crashes
- Display static and dynamic findings on separate result pages
- Classify findings as Critical, High, Medium or Low
- Calculate an overall risk score from 0 to 100
- Provide vulnerability evidence and remediation guidance
- Generate HTML and JSON security reports
- Support JWT-based authentication
- Access the same scan data from the website and Expo mobile application

> VulnScanner is intended only for educational use and authorized security testing. Do not scan applications without permission.

### High-Level Data Flow

1. The user logs in through the website or mobile application.
2. The backend verifies the account and returns a JWT access token.
3. The user chooses an APK and selects the required analysis types.
4. The client uploads the APK and scan configuration to Flask.
5. Flask validates the file and creates a scan record in SQLite.
6. The selected scanner engines run in a background thread.
7. Findings are filtered, scored and saved in the database.
8. The website and mobile application request progress and results from the API.
9. Static and dynamic results are displayed separately.

---

## Technology Stack

| Layer | Technologies |
|---|---|
| Web application | React 18, React Router, Axios, Tailwind CSS and Recharts |
| Web build tool | Vite |
| Mobile application | React Native, Expo SDK 54 and React Navigation |
| Mobile storage | AsyncStorage |
| Mobile file selection | Expo Document Picker |
| Backend API | Python and Flask |
| Authentication | JWT and Werkzeug password hashing |
| Database | SQLite and SQLAlchemy |
| Static analysis | Androguard, regular expressions and custom security rules |
| False-positive filtering | Shannon entropy, allow-lists and context-based scoring |
| Dynamic analysis | ADB, Android Emulator, Monkey, Logcat, AppOps and Dumpsys |
| Report generation | Jinja2, HTML and JSON |
| Testing | Pytest and pytest-flask |
| Deployment support | Docker and Docker Compose |

---

## Static Analysis

Static analysis examines an APK without running it. It is similar to opening a machine and inspecting its parts while it is switched off.

### Static Analysis Process

1. **APK validation**

   The scanner confirms that the uploaded file has a valid APK/ZIP structure. It checks for suspicious archive paths, decompression bombs, missing manifests and other file-integrity problems.

2. **Isolated APK parsing**

   Androguard runs inside a separate Python subprocess. It extracts:

   - Package name and application version
   - Android manifest
   - Permissions
   - Activities
   - Services
   - Broadcast receivers
   - Content providers
   - DEX strings
   - API calls
   - Native libraries

   The subprocess has a time limit. If parsing crashes or becomes stuck, the main Flask server can continue running.

3. **Manifest analysis**

   The manifest scanner checks for:

   - Debug mode enabled
   - Application backup enabled
   - Cleartext network traffic
   - Dangerous permissions
   - Exported components
   - Unprotected activities, services, receivers and providers
   - Insecure Android configuration

4. **Code and string analysis**

   The scanner searches the code and resources for:

   - Hardcoded API keys and authentication tokens
   - Passwords and private keys
   - Weak cryptographic algorithms
   - TLS validation bypasses
   - Insecure WebView settings
   - Unsafe file storage
   - Cleartext URLs
   - Dynamic code loading
   - Shell command execution
   - Suspicious or malware-like behaviour

5. **Data-flow analysis**

   The scanner looks for possible movement of sensitive information from a source, such as contacts or location, to a dangerous destination such as logs, files or network functions.

6. **Additional security checks**

   The scanner also examines:

   - Native `.so` libraries
   - APK certificates
   - Code obfuscation
   - Third-party SDKs
   - Privacy-related behaviour
   - Combinations of suspicious permissions and API calls

7. **False-positive filtering**

   Static findings can pass through an intelligent heuristic filter. The filter uses:

   - Known safe words such as `example`, `test` and `placeholder`
   - Known credential formats
   - Shannon entropy
   - Surrounding security-related words
   - Evidence length and source location
   - CWE, OWASP and severity information

   The filter is primarily rule and context based. It does not currently use a trained machine-learning model.

8. **Risk scoring**

   Findings are classified by severity and passed to the risk scorer. Critical and high-severity findings have a greater effect on the final score.

---

## Dynamic Analysis

Dynamic analysis installs and runs the APK inside a dedicated Android emulator. It observes what the application does during execution.

### Dynamic Analysis Process

1. Locate the ADB executable.
2. Find the configured Android emulator.
3. Confirm that the target is connected and authorized.
4. Reject physical devices unless explicitly permitted.
5. Install the APK and grant runtime permissions for testing.
6. Inspect the installed package configuration.
7. Clear old Logcat output.
8. Resolve and start the application's launcher activity.
9. Confirm that the application process is running.
10. Use Android Monkey to send controlled interface events.
11. Check JDWP and WebView debugging exposure.
12. Query privacy-sensitive operations through Android AppOps.
13. Collect application-related Logcat output.
14. Search logs for credentials, tokens, private keys and payment data.
15. Look for cleartext communication and TLS validation problems.
16. Detect runtime crashes and application-not-responding events.
17. Inspect accessible external and private application storage.
18. Collect process and memory diagnostics.
19. Store findings and runtime coverage information.
20. Force-stop and uninstall the tested application.

### Dynamic Checks

The dynamic engine can identify evidence of:

- Runtime debugging exposure
- Test-only application builds
- Backup-enabled applications
- Cleartext network configuration
- Sensitive information written to Logcat
- Passwords, tokens and JWTs exposed during execution
- API and cloud credentials
- Payment card information
- Cleartext URLs
- TLS validation bypass indicators
- Sensitive information in accessible storage
- Unsafe file permissions
- Application crashes and ANRs
- Privacy-sensitive Android operations

Dynamic analysis reports only behaviour that it actually observes. If an automated action does not reach a vulnerable screen or feature, that vulnerability may not appear in the dynamic results.

---

## Installation Instructions

### Prerequisites

Install the following tools:

- Python 3.11 or newer
- Node.js 18 or newer
- npm
- Git
- Android Studio and Android SDK Platform Tools for dynamic analysis
- Expo Go on an Android phone for the mobile application

### 1. Clone the Repository

```bash
git clone https://github.com/this username/VulnScanner-Android-Security-Scanner.git
cd VulnScanner-Android-Security-Scanner
```

Replace `YOUR-USERNAME` with your GitHub username.

### 2. Install the Backend

#### Windows PowerShell

```powershell
cd backend
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```

#### Linux or macOS

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

The backend starts at:

```text
http://localhost:5000
```

Check its status at:

```text
http://localhost:5000/api/health
```

### 3. Install the Website

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the website at:

```text
http://localhost:3000
```

The Vite development server forwards `/api` requests to the Flask backend on port `5000`.

### 4. Optional Docker Setup

The backend, website and Redis services can also be started with Docker:

```bash
docker compose up --build
```

After startup:

- Website: `http://localhost:3000`
- Backend: `http://localhost:5000`

> Dynamic analysis requires ADB access to the host emulator. Additional Docker device and networking configuration may be required. Running the Flask backend directly on the host is recommended for local dynamic-analysis demonstrations.

---

## Emulator Configuration

Dynamic analysis requires a dedicated Android emulator because the APK must be installed and executed in a controlled Android environment.

### 1. Install Android Studio

Download and install Android Studio:

```text
https://developer.android.com/studio
```

During installation, include:

- Android SDK
- Android SDK Platform Tools
- Android Emulator
- Android Virtual Device tools

### 2. Create an Emulator

1. Open Android Studio.
2. Open **Device Manager**.
3. Select **Create Device**.
4. Choose a device such as Pixel 6.
5. Select an Android system image.
6. Complete the setup.
7. Start the emulator.

Use a dedicated emulator that does not contain personal accounts or information.

### 3. Confirm ADB Connection

Run:

```powershell
adb devices -l
```

Example output:

```text
emulator-5554    device product:sdk_gphone64_x86_64
```

The first value is the emulator serial.

If `adb` is not recognized, use the complete path:

```powershell
C:\Users\YOUR-NAME\AppData\Local\Android\Sdk\platform-tools\adb.exe devices -l
```

### 4. Configure the Backend

Open `backend/.env` and update:

```env
DYNAMIC_ANALYSIS_DEVICE=emulator-
DYNAMIC_ALLOW_PHYSICAL=false
DYNAMIC_MONKEY_EVENTS=150
DYNAMIC_ANALYSIS_TIMEOUT=90
DYNAMIC_DEEP_MONKEY_EVENTS=500
DYNAMIC_DEEP_ANALYSIS_TIMEOUT=180
```

If ADB is not available through the system PATH, add:

```env
ANDROID_ADB_PATH=C:\Users\YOUR-NAME\AppData\Local\Android\Sdk\platform-tools\adb.exe
```

Replace the path and emulator serial with the values from your computer.

Restart the Flask backend after changing `.env`:

```powershell
cd backend
.\venv\Scripts\Activate.ps1
python app.py
```

### 5. Verify the Emulator

Before starting a dynamic scan, confirm:

- The emulator is running.
- Android has completed booting.
- The screen is unlocked.
- `adb devices -l` shows the emulator as `device`.
- The serial matches `DYNAMIC_ANALYSIS_DEVICE`.
- The Flask backend was restarted after configuration changes.

---

## Running the Website

1. Start the Android emulator if dynamic analysis will be used.
2. Start the Flask backend:

```powershell
cd backend
.\venv\Scripts\Activate.ps1
python app.py
```

3. Open another terminal and start the website:

```powershell
cd frontend
npm install
npm run dev
```

4. Open:

```text
http://localhost:3000
```

5. Log in or create an account.
6. Open **New Scan**.
7. Select an APK file.
8. Enable static analysis, dynamic analysis or both.
9. Start the scan.
10. Open the scan overview to monitor progress.
11. Use **Static Scan Results** and **Dynamic Scan Results** to view the separate findings.

---

## Running the Mobile App with Expo Go

The Expo mobile application connects to the same Flask backend and SQLite database as the website.

### 1. Prepare the Phone and Computer

- Install Expo Go on the Android phone.
- Connect the phone and computer to the same Wi-Fi network.
- Ensure Windows Firewall allows inbound connections to port `5000`.
- Keep the Flask backend running.

### 2. Find the Computer's IP Address

Run:

```powershell
ipconfig
```

Find the IPv4 address of the active Wi-Fi adapter.

Example:

```text
192.168.1.105
```

Do not use `localhost` or `127.0.0.1` on a physical phone. Those addresses refer to the phone itself.

### 3. Configure the Mobile Backend Address

Open PowerShell in the mobile project:

```powershell
cd mobile
$env:EXPO_PUBLIC_API_URL="http://192.168.1.105:5000"
```

Replace `192.168.1.105` with the computer's actual IPv4 address.

### 4. Start Expo

```powershell
npm install
npm start
```

Alternatively:

```powershell
npx expo start
```

Scan the displayed QR code using Expo Go.

If the mobile app uses an old address, restart Expo with its cache cleared:

```powershell
npx expo start -c
```

### 5. Use the Mobile Application

1. Open VulnScanner through Expo Go.
2. Confirm that the displayed backend address is correct.
3. Log in using the same account as the website.
4. Open **New Scan**.
5. Select an APK from the phone.
6. Enable static analysis, dynamic analysis or both.
7. Upload the APK.
8. Monitor the scan progress.
9. Open the separate static or dynamic result screens.

### Important Expo and Emulator Difference

Expo Go runs the VulnScanner client application on the phone. It does not perform dynamic analysis on that phone.

Dynamic analysis still happens through the Flask backend using the dedicated Android emulator connected to the computer:

```text
Expo Go phone → Flask backend → ADB → Android test emulator
```

Therefore, the Android test emulator must still be running when dynamic analysis is selected.

### Expo Troubleshooting

| Problem | Solution |
|---|---|
| Mobile app cannot reach the backend | Confirm the phone and computer use the same Wi-Fi network |
| Connection uses `127.0.0.1` | Set `EXPO_PUBLIC_API_URL` to the computer's IPv4 address |
| Connection times out | Allow Python or port `5000` through Windows Firewall |
| Old backend address remains | Run `npx expo start -c` |
| QR code does not open | Restart Expo and Expo Go |
| APK cannot be selected | Confirm Expo Document Picker is installed and allow file access |
| Dynamic scan fails | Start the emulator and verify `adb devices -l` |
| Configured emulator is unavailable | Correct `DYNAMIC_ANALYSIS_DEVICE` in `backend/.env` and restart Flask |
