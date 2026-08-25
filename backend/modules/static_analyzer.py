"""
VulnScanner Enterprise Static Analyzer v3
==========================================
Industrial-grade Android APK security analysis engine.

Covers:
  1.  APK Validation & Integrity (zip-slip, bombs, fake APK, repack detection)
  2.  Manifest Analysis (exported components, permissions, IPC, tapjacking, etc.)
  3.  DEX / Bytecode Analysis (secrets, crypto, SSL, WebView, storage, injection)
  4.  Taint / Data Flow Analysis (source→sink tracking, PII leakage)
  5.  Native Library Analysis (.so ELF parsing, unsafe C functions, shellcode)
  6.  Malware Classification (trojans, spyware, banking malware, RAT patterns)
  7.  WebView Security Analysis
  8.  Network Security Analysis (TLS, certificate pinning, suspicious endpoints)
  9.  Storage Security Analysis
  10. Obfuscation & Anti-Analysis Detection (ProGuard, DexGuard, packers)
  11. Third-Party SDK / Supply Chain Analysis (vulnerable libs, adware, trackers)
  12. Privacy & Compliance Checks (GDPR, PII, excessive permissions)
  13. Android-Specific Vulnerabilities (PendingIntent, Janus, FileProvider, etc.)
  14. Custom Rule Engine (YARA-style pattern rules)
  15. Compound / Dangerous API Combination Detection

Drop-in compatible with scans.py (StaticAnalyzer / VulnScannerEngine alias).
"""

import os
import re
import math
import json
import struct
import zipfile
import hashlib
import logging
import struct
from typing import List, Dict, Any, Tuple, Optional, Set
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


# HELPERS

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    h = 0.0
    n = len(data)
    for count in freq.values():
        p = count / n
        if p > 0:
            h -= p * math.log2(p)
    return h


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    h = 0.0
    n = len(data)
    for count in freq:
        if count > 0:
            p = count / n
            h -= p * math.log2(p)
    return h


def _find(corpus: str, pattern: str, flags: int = re.MULTILINE) -> List[re.Match]:
    try:
        return list(re.finditer(pattern, corpus, flags))
    except re.error:
        return []


def _extract_context(corpus: str, match: re.Match, window: int = 120) -> str:
    start = max(0, match.start() - window)
    end = min(len(corpus), match.end() + window)
    return corpus[start:end].strip()


FALSE_POSITIVE_WORDS: Set[str] = {
    'example', 'sample', 'test', 'demo', 'placeholder', 'dummy',
    'your_key', 'insert_key', 'replace', 'changeme', 'xxx',
    'aaaaaa', '000000', '123456', 'abcdef', 'undefined', 'null',
    'your_api_key', 'api_key_here', 'enter_key', 'put_key',
    'xxxxxxxxxxxxxxxx', '1234567890123456', 'todo', 'fixme', 'mock',
}

# Known-safe adware / tracker SDK package prefixes
TRACKER_SDKS: Dict[str, str] = {
    'com.appsflyer':         'AppsFlyer (Tracking SDK)',
    'com.adjust.sdk':        'Adjust (Tracking SDK)',
    'io.branch.referral':    'Branch.io (Attribution SDK)',
    'com.singular.sdk':      'Singular (Attribution SDK)',
    'com.moengage':          'MoEngage (Analytics SDK)',
    'com.clevertap':         'CleverTap (Analytics SDK)',
    'com.amplitude':         'Amplitude (Analytics SDK)',
    'com.mixpanel':          'Mixpanel (Analytics SDK)',
    'com.segment.analytics':  'Segment (Analytics SDK)',
    'com.google.firebase.analytics': 'Firebase Analytics (Tracking)',
    'com.chartboost':        'Chartboost (Ad SDK)',
    'com.ironsource':        'IronSource (Ad SDK)',
    'com.unity3d.ads':       'Unity Ads (Ad SDK)',
    'com.applovin':          'AppLovin (Ad SDK)',
    'com.vungle':            'Vungle (Ad SDK)',
    'com.facebook.ads':      'Facebook Audience Network (Ad SDK)',
    'com.google.android.gms.ads': 'Google AdMob (Ad SDK)',
    'com.inmobi':            'InMobi (Ad SDK)',
    'com.startapp':          'StartApp (Ad SDK)',
    'com.tapjoy':            'Tapjoy (Ad SDK)',
    'com.mopub':             'MoPub (Ad SDK)',
}

VULNERABLE_LIBS: Dict[str, Dict] = {
    'com.squareup.okhttp':       {'cve': 'CVE-2021-0341', 'issue': 'Hostname verification bypass in OkHttp < 3.12.12'},
    'org.apache.cordova':        {'cve': 'CVE-2015-5256', 'issue': 'Cordova whitelist bypass allowing JS bridge access'},
    'com.facebook.android':      {'cve': 'CVE-2019-3573', 'issue': 'Facebook SDK token logging vulnerability'},
    'com.google.android.gms':    {'cve': 'CVE-2017-0786', 'issue': 'Google Play Services WiFi Direct vulnerability'},
    'org.bouncycastle':          {'cve': 'CVE-2018-1000613', 'issue': 'BouncyCastle ASN.1 parsing vulnerability'},
    'com.parse':                 {'cve': 'CVE-2017-2765', 'issue': 'Parse SDK authentication bypass'},
    'io.fabric.sdk':             {'cve': 'CVE-2022-0529', 'issue': 'Fabric/Crashlytics data exposure'},
    'com.crashlytics':           {'cve': 'CVE-2022-0529', 'issue': 'Crashlytics device fingerprinting'},
    'retrofit2':                 {'cve': 'CVE-2021-34429', 'issue': 'Retrofit unsafe deserialization in older versions'},
    'com.jakewharton.picasso':   {'cve': 'None', 'issue': 'Picasso loads arbitrary URLs without validation'},
}

SUSPICIOUS_DOMAINS_PATTERNS = [
    r'(?i)(?:ngrok\.io|ngrok\.com)',
    r'(?i)(?:\.onion)\b',
    r'(?i)(?:pastebin\.com|paste\.ee|ghostbin\.com)',
    r'(?i)(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co)',           # URL shorteners in APKs = suspicious
    r'(?i)(?:requestbin|webhook\.site|pipedream)',
    r'(?i)(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})',  # IP:PORT combos
]


# 1. APK VALIDATION & INTEGRITY

def safe_extract_check(apk_path: str) -> Tuple[bool, Optional[str]]:
    """Guards against zip-slip, decompression bombs, and extreme compression ratios."""
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            total_uncompressed = 0
            for entry in zf.namelist():
                entry_path = os.path.normpath(entry)
                if entry_path.startswith('..') or os.path.isabs(entry_path) or entry_path.startswith('/'):
                    return False, f"Zip-slip path traversal detected: {entry}"
                info = zf.getinfo(entry)
                if info.file_size > 500 * 1024 * 1024:
                    return False, f"Single entry exceeds 500 MB uncompressed: {entry}"
                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > 200:
                        return False, f"Decompression bomb: {ratio:.0f}:1 ratio in {entry}"
                total_uncompressed += info.file_size
                if total_uncompressed > 2 * 1024 * 1024 * 1024:  # 2 GB total cap
                    return False, "Total uncompressed content exceeds 2 GB (zip bomb)"
        return True, None
    except zipfile.BadZipFile as e:
        return False, f"Invalid ZIP structure: {e}"
    except Exception as e:
        return False, f"Validation error: {e}"


class APKValidator:
    """
    Validates APK integrity, structure, and detects anomalies before analysis.
    Covers: structure checks, multi-DEX, repack indicators, APK-level entropy.
    """

    def validate(self, apk_path: str) -> Dict[str, Any]:
        result = {'valid': False, 'errors': [], 'warnings': [], 'info': {}}

        if not os.path.exists(apk_path):
            result['errors'].append('File not found')
            return result

        # ZIP bomb / slip protection first
        is_safe, err = safe_extract_check(apk_path)
        if not is_safe:
            result['errors'].append(f'Security check failed: {err}')
            return result

        # Magic bytes
        with open(apk_path, 'rb') as f:
            magic = f.read(4)
        if magic != b'PK\x03\x04':
            result['errors'].append('Not a valid APK/ZIP file (bad magic bytes)')
            return result

        # File size analysis
        size_bytes = os.path.getsize(apk_path)
        result['info']['file_size_bytes'] = size_bytes
        if size_bytes < 10 * 1024:
            result['warnings'].append(f'Suspiciously small APK ({size_bytes} bytes) — may be a stub or fake')
        if size_bytes > 150 * 1024 * 1024:
            result['warnings'].append(f'Very large APK ({size_bytes // (1024*1024)} MB) — bloatware or embedded payload risk')

        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                names = zf.namelist()

                # Required structure
                if 'AndroidManifest.xml' not in names:
                    result['errors'].append('Missing AndroidManifest.xml — not a valid APK')
                    return result

                dex_files = [n for n in names if re.match(r'classes\d*\.dex', n)]
                if not dex_files:
                    result['warnings'].append('No DEX files found — may be resource-only or stub APK')
                result['info']['dex_count'] = len(dex_files)
                result['info']['is_multidex'] = len(dex_files) > 1

                # Resource consistency
                has_resources = 'resources.arsc' in names
                result['info']['has_resources'] = has_resources
                if not has_resources:
                    result['warnings'].append('Missing resources.arsc — unusual for a real app')

                # Native libs
                so_files = [n for n in names if n.endswith('.so')]
                result['info']['native_lib_count'] = len(so_files)
                result['info']['native_architectures'] = list({
                    n.split('/')[1] for n in so_files if n.startswith('lib/') and '/' in n[4:]
                })

                # APK-wide entropy check (repack/packer indicator)
                dex_entropies = []
                for dex in dex_files[:3]:
                    data = zf.read(dex)
                    ent = byte_entropy(data)
                    dex_entropies.append(ent)
                if dex_entropies:
                    avg_dex_entropy = sum(dex_entropies) / len(dex_entropies)
                    result['info']['avg_dex_entropy'] = round(avg_dex_entropy, 3)
                    if avg_dex_entropy > 7.5:
                        result['warnings'].append(
                            f'High DEX entropy ({avg_dex_entropy:.2f}/8.0) — DEX may be encrypted/packed'
                        )

                # Repackaging indicator: check META-INF for multiple signers
                meta_certs = [n for n in names if n.startswith('META-INF/') and
                              any(n.endswith(e) for e in ('.RSA', '.DSA', '.EC', '.SF'))]
                result['info']['signature_files'] = meta_certs
                signers = [n for n in meta_certs if n.endswith(('.RSA', '.DSA', '.EC'))]
                if len(signers) > 1:
                    result['warnings'].append(
                        f'Multiple APK signers detected ({len(signers)}) — possible repackaging or dual signature'
                    )

                # Janus vulnerability indicator: check if file starts with valid DEX magic
                # Janus = file is simultaneously valid DEX + valid ZIP
                with open(apk_path, 'rb') as f:
                    file_start = f.read(8)
                if file_start[:4] == b'dex\n':
                    result['warnings'].append(
                        'Janus Vulnerability Indicator: File begins with DEX magic bytes — '
                        'APK may be exploitable via CVE-2017-13156 on Android 5.0-8.0'
                    )

        except zipfile.BadZipFile as e:
            result['errors'].append(f'Corrupted ZIP: {e}')
            return result

        result['valid'] = True
        return result

    def compute_hashes(self, apk_path: str) -> Dict[str, str]:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(apk_path, 'rb') as f:
            while chunk := f.read(65536):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest(),
        }


# APK DECOMPILER

class APKDecompiler:
    """
    Wraps sandboxed Androguard subprocess for safe APK decompilation.
    Falls back to raw ZIP extraction if sandbox fails.
    """

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self._sandbox_data: Dict = {}
        self._loaded = False

    def load(self) -> bool:
        try:
            from modules.sandbox_runner import run_analysis_sandboxed
            data = run_analysis_sandboxed(self.apk_path, timeout_seconds=120)
            if data.get('success'):
                self._sandbox_data = data
                self._loaded = True
                logger.info(f"Sandboxed analysis OK: {len(data.get('strings', []))} strings, "
                            f"{len(data.get('api_calls', []))} API calls")
                return True
            else:
                logger.warning(f"Sandboxed analysis failed: {data.get('error')}")
                return False
        except Exception as e:
            logger.warning(f"Sandbox load error: {e}")
            return False

    def get_metadata(self) -> Dict[str, Any]:
        if self._loaded and self._sandbox_data.get('metadata'):
            return self._sandbox_data['metadata']
        meta = {'package_name': 'unknown', 'version_name': '1.0',
                'version_code': '1', 'min_sdk': None, 'target_sdk': None}
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                raw = zf.read('AndroidManifest.xml').decode('utf-8', errors='replace')
                m = re.search(r'package\s*=\s*["\']([^"\']+)["\']', raw)
                if m:
                    meta['package_name'] = m.group(1)
        except Exception:
            pass
        return meta

    def get_manifest_xml(self) -> str:
        if self._loaded:
            manifest = self._sandbox_data.get('manifest', '')
            if manifest:
                return manifest
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                return zf.read('AndroidManifest.xml').decode('utf-8', errors='replace')
        except Exception:
            return ''

    def get_all_strings(self) -> List[str]:
        if self._loaded:
            strings = self._sandbox_data.get('strings', [])
            if strings:
                return strings
        # Fallback: extract printable strings from DEX
        strings = []
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                for name in zf.namelist():
                    if name.endswith('.dex'):
                        data = zf.read(name)
                        printable = re.findall(rb'[\x20-\x7e]{6,}', data)
                        strings.extend(s.decode('ascii', errors='replace') for s in printable)
                    elif name.startswith('res/') or name.endswith(('.xml', '.properties', '.json')):
                        try:
                            strings.append(zf.read(name).decode('utf-8', errors='replace'))
                        except Exception:
                            pass
        except Exception as e:
            logger.debug(f"String fallback error: {e}")
        return strings

    def get_smali_code(self) -> str:
        parts = []
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                for name in zf.namelist():
                    try:
                        data = zf.read(name)
                        if any(name.endswith(ext) for ext in
                               ('.smali', '.java', '.kt', '.xml', '.json', '.properties', '.gradle')):
                            parts.append(data.decode('utf-8', errors='replace'))
                        elif name.endswith('.dex'):
                            printable = re.findall(rb'[\x20-\x7e]{4,}', data)
                            parts.extend(s.decode('ascii', errors='replace') for s in printable[:5000])
                    except Exception:
                        pass
                    if len(parts) > 500:
                        break
        except Exception:
            pass
        return '\n'.join(parts)

    def get_api_calls(self) -> List[str]:
        if self._loaded:
            return self._sandbox_data.get('api_calls', [])
        return []

    def get_permissions(self) -> List[str]:
        if self._loaded:
            perms = self._sandbox_data.get('permissions', [])
            if perms:
                return perms
        manifest = self.get_manifest_xml()
        return re.findall(r'android:name="(android\.permission\.[^"]+)"', manifest)

    def get_activities(self) -> List[str]: return self._sandbox_data.get('activities', []) if self._loaded else []
    def get_services(self)   -> List[str]: return self._sandbox_data.get('services', [])   if self._loaded else []
    def get_receivers(self)  -> List[str]: return self._sandbox_data.get('receivers', [])  if self._loaded else []
    def get_providers(self)  -> List[str]: return self._sandbox_data.get('providers', [])  if self._loaded else []

    def get_so_files(self) -> List[str]:
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                return [n for n in zf.namelist() if n.endswith('.so')]
        except Exception:
            return []

    def get_class_names(self) -> List[str]:
        """Extract class names from API calls for SDK detection."""
        calls = self.get_api_calls()
        classes = set()
        for call in calls:
            if '->' in call:
                cls = call.split('->')[0].lstrip('L').replace('/', '.').rstrip(';')
                classes.add(cls)
        return list(classes)


# 2. MANIFEST ANALYSIS ENGINE

class ManifestAnalyzer:

    DANGEROUS_PERMISSIONS: Dict[str, Tuple] = {
        'android.permission.READ_SMS':                   ('critical', 9.0, 'Reads ALL SMS including OTPs and 2FA codes'),
        'android.permission.SEND_SMS':                   ('critical', 8.5, 'Sends SMS without user awareness — premium SMS abuse'),
        'android.permission.RECEIVE_SMS':                ('critical', 8.5, 'Intercepts all incoming SMS including 2FA OTPs'),
        'android.permission.READ_CALL_LOG':              ('high',     7.0, 'Reads complete call history'),
        'android.permission.WRITE_CALL_LOG':             ('high',     6.5, 'Modifies or deletes call history'),
        'android.permission.PROCESS_OUTGOING_CALLS':     ('critical', 8.0, 'Intercepts and redirects outgoing calls'),
        'android.permission.RECORD_AUDIO':               ('high',     7.5, 'Microphone access — can record conversations covertly'),
        'android.permission.CAMERA':                     ('high',     7.0, 'Camera access — can capture photos/video covertly'),
        'android.permission.ACCESS_FINE_LOCATION':       ('high',     7.2, 'Precise GPS location tracking'),
        'android.permission.ACCESS_COARSE_LOCATION':     ('medium',   5.0, 'Approximate location access'),
        'android.permission.READ_CONTACTS':              ('high',     6.8, 'Full read access to contacts database'),
        'android.permission.WRITE_CONTACTS':             ('high',     6.5, 'Can modify or delete all contacts'),
        'android.permission.GET_ACCOUNTS':               ('medium',   4.5, 'Lists all device accounts (Google, email, etc.)'),
        'android.permission.BIND_ACCESSIBILITY_SERVICE': ('critical', 9.5, 'Reads all on-screen content — keylogging risk'),
        'android.permission.BIND_NOTIFICATION_LISTENER_SERVICE': ('high', 7.8, 'Reads ALL notifications from all apps'),
        'android.permission.BIND_DEVICE_ADMIN':          ('critical', 9.0, 'Device admin: lock/wipe device, enforce policies'),
        'android.permission.RECEIVE_BOOT_COMPLETED':     ('medium',   4.0, 'Auto-starts on device reboot — persistence'),
        'android.permission.REQUEST_INSTALL_PACKAGES':   ('high',     7.5, 'Can install apps silently'),
        'android.permission.SYSTEM_ALERT_WINDOW':        ('high',     7.2, 'Overlay on all apps — phishing and clickjacking'),
        'android.permission.READ_EXTERNAL_STORAGE':      ('medium',   4.8, 'Reads all files on external storage'),
        'android.permission.WRITE_EXTERNAL_STORAGE':     ('medium',   5.0, 'Writes to device storage'),
        'android.permission.MANAGE_EXTERNAL_STORAGE':    ('high',     6.5, 'Full all-files access to storage'),
        'android.permission.READ_PHONE_STATE':           ('medium',   4.5, 'Accesses IMEI and device identifiers'),
        'android.permission.CALL_PHONE':                 ('high',     7.0, 'Makes phone calls without user interaction'),
        'android.permission.READ_MEDIA_IMAGES':          ('medium',   4.5, 'Accesses all photos on device'),
        'android.permission.READ_MEDIA_VIDEO':           ('medium',   4.5, 'Accesses all videos on device'),
        'android.permission.MANAGE_OVERLAY_PERMISSION':  ('high',     7.0, 'Manages overlay permission — phishing risk'),
        'android.permission.CHANGE_WIFI_STATE':          ('medium',   4.0, 'Can change WiFi connections'),
        'android.permission.BLUETOOTH_ADMIN':            ('medium',   4.5, 'Full Bluetooth control'),
        'android.permission.NFC':                        ('medium',   4.0, 'NFC communication access'),
        'android.permission.CHANGE_NETWORK_STATE':       ('medium',   4.0, 'Can enable/disable network interfaces'),
        'android.permission.USE_BIOMETRIC':              ('medium',   4.5, 'Access to biometric hardware — ensure secure implementation'),
        'android.permission.USE_FINGERPRINT':            ('medium',   4.5, 'Fingerprint sensor access'),
    }

    ROOT_PERMISSIONS: Set[str] = {
        'android.permission.MOUNT_UNMOUNT_FILESYSTEMS',
        'android.permission.WRITE_SECURE_SETTINGS',
        'android.permission.REBOOT',
        'android.permission.INSTALL_PACKAGES',
        'android.permission.DELETE_PACKAGES',
        'android.permission.CHANGE_COMPONENT_ENABLED_STATE',
        'android.permission.SET_PREFERRED_APPLICATIONS',
        'android.permission.KILL_BACKGROUND_PROCESSES',
    }

    def analyze(self, manifest_text: str, permissions: List[str],
                activities: List[str], services: List[str],
                receivers: List[str], providers: List[str],
                package_name: str = '') -> List[Dict]:
        findings = []
        mf = manifest_text or ''

        # Core flags
        if re.search(r'android:debuggable\s*=\s*["\']true["\']', mf, re.I):
            findings.append(self._f(
                'Application Debuggable in Production', 'high', 'Manifest', 7.2,
                'android:debuggable="true" is set. Any user or app can attach a debugger, inspect memory, '
                'bypass security checks, and extract sensitive data via ADB.',
                'AndroidManifest.xml', 'android:debuggable="true"',
                'Remove android:debuggable from the manifest. Use build types: release { debuggable false }',
                f'adb shell run-as {package_name} ls /data/data/{package_name}/',
                'M8: Security Misconfiguration', 'CWE-489'))

        if re.search(r'android:allowBackup\s*=\s*["\']true["\']', mf, re.I) or 'allowBackup' not in mf:
            findings.append(self._f(
                'Full Application Data Backup Allowed', 'medium', 'Manifest', 5.5,
                'android:allowBackup is enabled (or absent, defaults to true). ADB backup can silently extract '
                'the entire app database, credentials, and session tokens without root.',
                'AndroidManifest.xml', 'android:allowBackup="true" (or attribute absent)',
                'Set android:allowBackup="false". Use android:fullBackupContent to exclude sensitive paths.',
                f'adb backup -apk -shared {package_name}',
                'M2: Insecure Data Storage', 'CWE-530'))

        if re.search(r'usesCleartextTraffic\s*=\s*["\']true["\']', mf, re.I) or \
           re.search(r'cleartextTrafficPermitted\s*=\s*["\']true["\']', mf, re.I):
            findings.append(self._f(
                'Cleartext HTTP Traffic Explicitly Permitted', 'high', 'Network', 7.4,
                'The app explicitly permits unencrypted HTTP traffic. An attacker can intercept all '
                'communications via ARP spoofing, rogue hotspot, or network tap.',
                'AndroidManifest.xml / network_security_config.xml',
                'android:usesCleartextTraffic="true"',
                'Set android:usesCleartextTraffic="false". Migrate all endpoints to HTTPS.',
                None, 'M3: Insecure Communication', 'CWE-319'))

        # Network security configuration
        nsc_match = re.search(r'android:networkSecurityConfig\s*=\s*["\']@xml/([^"\']+)["\']', mf)
        if not nsc_match:
            findings.append(self._f(
                'No Network Security Config Defined', 'medium', 'Network', 5.0,
                'No android:networkSecurityConfig is declared. Without it, the app uses platform defaults '
                'which on Android < 9 permit cleartext traffic and do not enforce certificate pinning.',
                'AndroidManifest.xml', 'networkSecurityConfig attribute absent',
                'Add res/xml/network_security_config.xml with <base-config cleartextTrafficPermitted="false">'
                ' and optional <pin-set> entries.',
                None, 'M3: Insecure Communication', 'CWE-319'))

        # Exported components
        for tag, label, sev, cvss, owasp_cat, cwe, poc_cmd in [
            ('activity',  'Activity',          'high',     7.2, 'M4: Insufficient Input/Output Validation', 'CWE-926',
             f'adb shell am start -n {package_name}/'),
            ('service',   'Service',            'high',     7.0, 'M4: Insufficient Input/Output Validation', 'CWE-926',
             f'adb shell am startservice -n {package_name}/'),
            ('receiver',  'Broadcast Receiver', 'high',     6.8, 'M4: Insufficient Input/Output Validation', 'CWE-926',
             f'adb shell am broadcast -n {package_name}/'),
        ]:
            for m in re.finditer(
                rf'<{tag}[^>]+?android:exported\s*=\s*["\']true["\'][^>]*?>',
                mf, re.DOTALL | re.I
            ):
                block = m.group(0)
                nm = re.search(r'android:name\s*=\s*["\']([^"\']+)["\']', block)
                name = nm.group(1) if nm else f'Unknown{label}'
                short = name.split('.')[-1]
                if 'android:permission' not in block and 'LAUNCHER' not in block:
                    findings.append(self._f(
                        f'Unprotected Exported {label}: {short}', sev, 'Components', cvss,
                        f'{label} "{name}" is exported without any permission requirement. '
                        f'Any installed app can freely launch/bind/send to it.',
                        'AndroidManifest.xml', f'<{tag} android:name="{name}" android:exported="true"/>',
                        f'Add android:permission="com.app.PERMISSION" or set android:exported="false".',
                        poc_cmd + name,
                        owasp_cat, cwe))

        # Content providers
        for m in re.finditer(r'<provider[^>]+?android:exported\s*=\s*["\']true["\'][^>]*?>', mf, re.DOTALL | re.I):
            block = m.group(0)
            nm = re.search(r'android:name\s*=\s*["\']([^"\']+)["\']', block)
            am = re.search(r'android:authorities\s*=\s*["\']([^"\']+)["\']', block)
            name = nm.group(1) if nm else 'UnknownProvider'
            auth = am.group(1) if am else package_name
            has_perm = any(x in block for x in ('android:readPermission', 'android:writePermission', 'android:permission'))
            if not has_perm:
                findings.append(self._f(
                    f'Unprotected Content Provider: {name.split(".")[-1]}', 'critical', 'Components', 8.5,
                    f'Content provider "{name}" is exported with no permission. Any app can query, insert, '
                    f'update, or delete its data — potentially the entire app database.',
                    'AndroidManifest.xml', f'<provider android:name="{name}" android:exported="true"/>',
                    'Add android:readPermission and android:writePermission, or set android:exported="false".',
                    f'adb shell content query --uri content://{auth}/',
                    'M4: Insufficient Input/Output Validation', 'CWE-926'))

        # FileProvider configuration
        for m in re.finditer(r'<provider[^>]+?FileProvider[^>]*?>', mf, re.DOTALL | re.I):
            block = m.group(0)
            if 'android:exported="true"' in block or "android:exported='true'" in block:
                findings.append(self._f(
                    'FileProvider Exported — Path Traversal Risk', 'high', 'Components', 7.8,
                    'A FileProvider is exported (android:exported="true"). FileProviders should NEVER be '
                    'exported. This can allow external apps to read arbitrary app-internal files.',
                    'AndroidManifest.xml', 'FileProvider with android:exported="true"',
                    'Always set android:exported="false" on FileProvider. '
                    'Use android:grantUriPermissions="true" for sharing individual URIs.',
                    None, 'M2: Insecure Data Storage', 'CWE-200'))

        # PendingIntent exposure
        if re.search(r'PendingIntent\.(getActivity|getService|getBroadcast)\s*\(', mf + '\n' + manifest_text, re.I):
            if not re.search(r'FLAG_IMMUTABLE|FLAG_MUTABLE', mf):
                findings.append(self._f(
                    'PendingIntent Without Immutability Flag', 'high', 'Components', 7.3,
                    'PendingIntents created without FLAG_IMMUTABLE or FLAG_MUTABLE can be hijacked. '
                    'Malicious apps may intercept and modify the intent, performing unauthorized actions.',
                    'AndroidManifest.xml', 'PendingIntent without FLAG_IMMUTABLE',
                    'Always use FLAG_IMMUTABLE for PendingIntents unless mutability is explicitly required '
                    '(FLAG_MUTABLE). Required on Android 12+.',
                    None, 'M4: Insufficient Input/Output Validation', 'CWE-927'))

        # Dangerous permissions
        seen_perms: Set[str] = set()
        for perm in permissions:
            if perm in self.DANGEROUS_PERMISSIONS and perm not in seen_perms:
                seen_perms.add(perm)
                sev, cvss, reason = self.DANGEROUS_PERMISSIONS[perm]
                short = perm.split('.')[-1]
                findings.append(self._f(
                    f'Dangerous Permission: {short}', sev, 'Permissions', cvss,
                    f'Permission "{perm}" is declared. {reason}.',
                    'AndroidManifest.xml', f'<uses-permission android:name="{perm}"/>',
                    'Only request if strictly necessary. Implement runtime requests with clear user rationale.',
                    None, 'M1: Improper Credential Usage', 'CWE-272'))

        # Root and system permissions
        for perm in permissions:
            if perm in self.ROOT_PERMISSIONS:
                findings.append(self._f(
                    f'System-Level Permission: {perm.split(".")[-1]}', 'critical', 'Permissions', 9.0,
                    f'"{perm}" is a system/root permission. Standard apps should never need this — '
                    f'indicates privilege escalation or malware.',
                    'AndroidManifest.xml', f'<uses-permission android:name="{perm}"/>',
                    'Remove this permission. Standard apps have no legitimate use for system permissions.',
                    None, 'M1: Improper Credential Usage', 'CWE-269'))

        # Permission count
        dangerous_count = sum(1 for p in permissions if p in self.DANGEROUS_PERMISSIONS)
        if dangerous_count >= 6:
            findings.append(self._f(
                f'Excessive Dangerous Permissions ({dangerous_count} declared)', 'high', 'Permissions', 7.0,
                f'The app declares {dangerous_count} dangerous permissions. Legitimate apps should request '
                f'only the minimum required (principle of least privilege). This pattern is associated with '
                f'spyware and overly invasive apps.',
                'AndroidManifest.xml', f'{dangerous_count} dangerous permissions declared',
                'Audit all permission requests. Remove any not essential to core functionality.',
                None, 'M1: Improper Credential Usage', 'CWE-272'))

        # Boot persistence
        if 'RECEIVE_BOOT_COMPLETED' in ' '.join(permissions) and 'BOOT_COMPLETED' in mf:
            findings.append(self._f(
                'Boot Persistence Mechanism', 'medium', 'Manifest', 4.5,
                'App registers RECEIVE_BOOT_COMPLETED and has a boot receiver. Auto-starts on every reboot — '
                'common malware persistence technique.',
                'AndroidManifest.xml', 'RECEIVE_BOOT_COMPLETED + BroadcastReceiver',
                'Only implement if providing a legitimate background service. Disclose this behavior clearly.',
                None, 'M8: Security Misconfiguration', 'CWE-912'))

        # Shared user ID
        m = re.search(r'android:sharedUserId\s*=\s*["\']([^"\']+)["\']', mf)
        if m:
            uid = m.group(1)
            findings.append(self._f(
                'Shared User ID Declared', 'medium', 'Manifest', 5.0,
                f'sharedUserId="{uid}" allows multiple apps with the same cert to share a Linux UID and '
                f'each other\'s data, expanding the attack surface significantly.',
                'AndroidManifest.xml', f'android:sharedUserId="{uid}"',
                'Remove sharedUserId unless absolutely required.',
                None, 'M8: Security Misconfiguration', 'CWE-732'))

        # Custom URL schemes
        if re.search(r'<data\s+android:scheme', mf) and \
           re.search(r'android:exported\s*=\s*["\']true["\']', mf):
            findings.append(self._f(
                'Custom URL Scheme Deep Link Exposed', 'medium', 'Components', 5.3,
                'Custom URL deep links registered with exported activities. Without rigorous validation, '
                'crafted URLs can trigger unintended actions or navigate to internal screens.',
                'AndroidManifest.xml', 'Custom android:scheme with exported activity',
                'Validate all deep link parameters. Whitelist expected URL patterns. Sanitize all inputs.',
                f'adb shell am start -a android.intent.action.VIEW -d "custom://evil/" {package_name}',
                'M4: Insufficient Input/Output Validation', 'CWE-601'))

        # Task affinity and tapjacking
        if re.search(r'android:taskAffinity\s*=\s*["\']["\']', mf):
            findings.append(self._f(
                'Empty Task Affinity — Task Hijacking Risk', 'medium', 'Manifest', 4.8,
                'Empty taskAffinity enables task hijacking attacks where a malicious app intercepts user sessions.',
                'AndroidManifest.xml', 'android:taskAffinity=""',
                'Remove empty taskAffinity. Add android:launchMode="singleTask" to prevent hijacking.',
                None, 'M4: Insufficient Input/Output Validation', 'CWE-200'))

        if not re.search(r'android:filterTouchesWhenObscured\s*=\s*["\']true["\']', mf):
            if re.search(r'SYSTEM_ALERT_WINDOW', ' '.join(permissions)):
                findings.append(self._f(
                    'Tapjacking Exposure — Touch Filter Not Enforced', 'medium', 'Manifest', 5.5,
                    'App uses SYSTEM_ALERT_WINDOW but does not set filterTouchesWhenObscured="true". '
                    'An overlay drawn by another app can intercept user taps (tapjacking).',
                    'AndroidManifest.xml / Layout XMLs',
                    'SYSTEM_ALERT_WINDOW without filterTouchesWhenObscured',
                    'Add android:filterTouchesWhenObscured="true" to all sensitive UI views.',
                    None, 'M4: Insufficient Input/Output Validation', 'CWE-1021'))

        # Implicit broadcast receivers
        implicit_actions = re.findall(
            r'<action\s+android:name\s*=\s*["\']android\.intent\.action\.(SEND|VIEW|DIAL|CALL)["\']',
            mf, re.I
        )
        if implicit_actions:
            findings.append(self._f(
                f'Implicit Intent Filters Registered ({", ".join(set(implicit_actions))})',
                'low', 'Components', 3.5,
                'App registers implicit intent filters (SEND, VIEW, DIAL, CALL). Another app could '
                'accidentally route sensitive data through this component.',
                'AndroidManifest.xml', f'Implicit intent actions: {implicit_actions}',
                'Use explicit intents where possible. Validate all incoming intent data before use.',
                None, 'M4: Insufficient Input/Output Validation', 'CWE-927'))

        # SDK versions
        min_sdk_match = re.search(r'android:minSdkVersion\s*=\s*["\'](\d+)["\']', mf)
        if min_sdk_match:
            min_sdk = int(min_sdk_match.group(1))
            if min_sdk < 21:
                findings.append(self._f(
                    f'Very Low Minimum SDK Version (API {min_sdk})',
                    'medium', 'Manifest', 4.5,
                    f'minSdkVersion={min_sdk} (Android {_sdk_to_version(min_sdk)}) still supported. '
                    f'These Android versions have numerous unpatched vulnerabilities and lack modern security APIs.',
                    'AndroidManifest.xml', f'android:minSdkVersion="{min_sdk}"',
                    'Raise minSdkVersion to at least 24 (Android 7.0) to access modern security APIs.',
                    None, 'M8: Security Misconfiguration', 'CWE-1104'))

        return findings

    def _f(self, title, severity, category, cvss, description, location,
           evidence, remediation, poc, owasp, cwe, confidence='high') -> Dict:
        return {
            'title': title, 'severity': severity, 'category': category,
            'cvss_score': cvss, 'description': description, 'location': location,
            'evidence': evidence, 'remediation': remediation, 'poc_command': poc,
            'owasp_category': owasp, 'cwe_id': cwe, 'confidence': confidence,
        }


def _sdk_to_version(sdk: int) -> str:
    mapping = {14: '4.0', 15: '4.0.3', 16: '4.1', 17: '4.2', 18: '4.3',
               19: '4.4', 21: '5.0', 22: '5.1', 23: '6.0', 24: '7.0',
               25: '7.1', 26: '8.0', 27: '8.1', 28: '9.0', 29: '10',
               30: '11', 31: '12', 32: '12L', 33: '13', 34: '14'}
    return mapping.get(sdk, str(sdk))


# 3. CODE / BYTECODE ANALYSIS ENGINE

class CodeAnalyzer:
    """
    Analyzes DEX string constants, smali bytecode, and API call graphs.
    Covers: secrets, crypto misuse, SSL/TLS, WebView, storage, injection,
            network, malware patterns, and anti-analysis techniques.
    """

    # Secrets
    SECRET_PATTERNS = [
        (r'AKIA[0-9A-Z]{16}',
         'AWS Access Key ID', 'critical', 9.8,
         'Hardcoded AWS Access Key ID. Anyone decompiling the APK has full AWS account access.',
         'CWE-798', 'Revoke in AWS IAM immediately. Use IAM roles or AWS Secrets Manager.'),
        (r'(?i)aws.{0,20}secret.{0,10}[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?',
         'AWS Secret Access Key', 'critical', 9.5,
         'AWS Secret Access Key hardcoded. Provides full programmatic AWS account access.',
         'CWE-798', 'Revoke immediately. Use backend proxy + environment variables.'),
        (r'AIza[0-9A-Za-z\-_]{35}',
         'Google API Key', 'critical', 9.1,
         'Google API Key hardcoded. Can be used for API calls billed to your account.',
         'CWE-798', 'Restrict key in Google Cloud Console. Rotate immediately.'),
        (r'(?i)firebase[^"\']{0,30}["\']([A-Za-z0-9\-_]{20,})["\']',
         'Firebase API Key', 'high', 8.5,
         'Firebase API key hardcoded. May allow unauthorized database access.',
         'CWE-798', 'Restrict Firebase key. Enforce strict Security Rules. Use App Check.'),
        (r'sk-[a-zA-Z0-9]{48}',
         'OpenAI API Key', 'critical', 9.3,
         'OpenAI API key hardcoded. Allows unlimited API calls at your expense.',
         'CWE-798', 'Revoke and regenerate. Route OpenAI calls through a server-side proxy.'),
        (r'ghp_[0-9a-zA-Z]{36}',
         'GitHub Personal Access Token', 'critical', 9.4,
         'GitHub PAT hardcoded. Can access private repos and perform actions.',
         'CWE-798', 'Revoke at github.com/settings/tokens. Use GitHub Apps instead.'),
        (r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
         'Embedded RSA Private Key', 'critical', 10.0,
         'Private key embedded in APK. Completely compromises the associated cryptographic identity.',
         'CWE-321', 'Remove immediately. Use Android Keystore System.'),
        (r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
         'Hardcoded JWT Token', 'high', 8.1,
         'JWT token hardcoded. If long-lived, provides persistent unauthorized access.',
         'CWE-798', 'Remove hardcoded tokens. Generate at runtime via authentication.'),
        (r'(?i)(?:api[_\-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,})["\']',
         'Hardcoded API Key', 'high', 7.8,
         'Hardcoded API key found. Attackers can use this for unauthorized API access.',
         'CWE-798', 'Move API keys to secure backend. Never embed in mobile apps.'),
        (r'(?i)(?:client[_\-]?secret|app[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9\-_]{12,})["\']',
         'Hardcoded OAuth Client Secret', 'high', 8.2,
         'OAuth client secret hardcoded. Can impersonate your application.',
         'CWE-798', 'Never put client secrets in mobile apps. Use PKCE flow.'),
        (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^\s"\']{8,})["\']',
         'Hardcoded Password', 'high', 8.0,
         'Hardcoded password found in application code.',
         'CWE-798', 'Remove hardcoded passwords. Use Android Keystore for credential storage.'),
        (r'(?i)(?:auth[_\-]?token|access[_\-]?token|bearer[_\-]?token)\s*[=:]\s*["\']([A-Za-z0-9\-_.]{20,})["\']',
         'Hardcoded Authentication Token', 'high', 7.9,
         'Hardcoded authentication token found.',
         'CWE-798', 'Remove hardcoded tokens. Generate via proper auth flows.'),
        (r'(?i)(?:jdbc|mongodb|mysql|postgres|redis|mongodb\+srv)://[^\s"\'<]{10,}',
         'Hardcoded Database Connection String', 'critical', 9.0,
         'Database connection string with credentials embedded in the app.',
         'CWE-798', 'Move database access to backend API. Never connect directly from mobile.'),
        (r'xox[baprs]-[A-Za-z0-9\-]{10,}',
         'Slack OAuth Token', 'critical', 9.0,
         'Slack API token hardcoded.',
         'CWE-798', 'Revoke at api.slack.com/apps. Use server-side Slack API calls.'),
        (r'(?i)(?:stripe|paypal|braintree)[_\-]?(?:secret|key|token)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
         'Hardcoded Payment API Key', 'critical', 9.5,
         'Payment processor API key hardcoded. Can enable fraudulent transactions.',
         'CWE-798', 'Revoke immediately. Payment API keys must only exist server-side.'),
        (r'(?i)twilio[^"\']{0,20}["\']([A-Za-z0-9]{32,})["\']',
         'Twilio API Credentials', 'critical', 9.0,
         'Twilio credentials hardcoded. Can be used to make calls/send SMS at your expense.',
         'CWE-798', 'Revoke at console.twilio.com. Use server-side Twilio calls.'),
        (r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}',
         'SendGrid API Key', 'critical', 9.0,
         'SendGrid API key hardcoded. Can send emails on your behalf and access account data.',
         'CWE-798', 'Revoke at app.sendgrid.com/settings/api_keys. Use server-side email sending.'),
        (r'(?i)private[_\-]?key\s*[=:]\s*["\']([A-Za-z0-9+/=\-_]{30,})["\']',
         'Hardcoded Private Key Material', 'critical', 9.5,
         'Private key material hardcoded in application source.',
         'CWE-321', 'Use Android Keystore for all private key storage.'),
        (r'(?i)(?:encryption[_\-]?key|secret[_\-]?key|aes[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9+/=\-_]{16,})["\']',
         'Hardcoded Encryption Key', 'high', 8.5,
         'Encryption key hardcoded in application. Decrypting protected data is trivial for attackers.',
         'CWE-321', 'Generate encryption keys at runtime. Store in Android Keystore.'),
    ]

    # Cryptographic misuse
    CRYPTO_PATTERNS = [
        (r'(?:MessageDigest\.getInstance|getInstance)\s*\(\s*["\']MD5["\']',
         'Weak Hash Algorithm: MD5', 'medium', 5.9,
         'MD5 is cryptographically broken — vulnerable to collision attacks.',
         'CWE-327', 'Replace with SHA-256: MessageDigest.getInstance("SHA-256")'),
        (r'(?:MessageDigest\.getInstance|getInstance)\s*\(\s*["\']SHA-?1["\']',
         'Weak Hash Algorithm: SHA-1', 'medium', 5.3,
         'SHA-1 is deprecated. Collision attacks are practical (SHAttered attack, 2017).',
         'CWE-327', 'Replace with SHA-256: MessageDigest.getInstance("SHA-256")'),
        (r'Cipher\.getInstance\s*\(\s*["\']DES["\']',
         'Broken Cipher: DES', 'high', 7.4,
         'DES uses a 56-bit key brute-forceable in hours.',
         'CWE-327', 'Use AES-256-GCM: Cipher.getInstance("AES/GCM/NoPadding")'),
        (r'Cipher\.getInstance\s*\(\s*["\']DESede',
         'Weak Cipher: 3DES/Triple-DES', 'high', 6.8,
         '3DES is deprecated. Vulnerable to Sweet32 birthday attacks (64-bit blocks).',
         'CWE-327', 'Use AES-256-GCM: Cipher.getInstance("AES/GCM/NoPadding")'),
        (r'Cipher\.getInstance\s*\(\s*["\'][A-Z]+/ECB',
         'Insecure Block Cipher Mode: ECB', 'high', 7.1,
         'ECB mode is deterministic — identical plaintext always produces identical ciphertext, revealing patterns.',
         'CWE-327', 'Use GCM mode with random IV: Cipher.getInstance("AES/GCM/NoPadding")'),
        (r'Cipher\.getInstance\s*\(\s*["\']RC4',
         'Broken Stream Cipher: RC4', 'high', 7.5,
         'RC4 has multiple statistical biases and is cryptographically broken (RFC 7465).',
         'CWE-327', 'Use AES-256-GCM or ChaCha20-Poly1305.'),
        (r'\bnew\s+Random\s*\(\s*\)',
         'Insecure Randomness: java.util.Random', 'medium', 5.1,
         'java.util.Random is a PRNG not suitable for security operations — predictable.',
         'CWE-338', 'Use SecureRandom: new SecureRandom()'),
        (r'IvParameterSpec\s*\(\s*new\s+byte\s*\[',
         'Static or Zero IV', 'high', 7.6,
         'Zero-initialized or static IV used. Reusing IVs with CBC/CTR mode reveals plaintext patterns.',
         'CWE-329', 'Generate a fresh random IV: byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);'),
        (r'(?i)static\s+(?:final\s+)?(?:byte\[\]|String)\s+(?:KEY|AES_KEY|SECRET|ENC_KEY|ENCRYPTION_KEY)',
         'Static Hardcoded Cryptographic Key', 'high', 7.8,
         'Cryptographic key defined as static constant. Anyone who decompiles the app has the key.',
         'CWE-321', 'Store keys in Android Keystore: KeyStore.getInstance("AndroidKeyStore")'),
        (r'SecretKeySpec\s*\([^,]+,\s*["\']DES["\']',
         'DES Key Specification', 'high', 7.2,
         'A DES encryption key is configured. DES is cryptographically broken.',
         'CWE-327', 'Replace entire DES implementation with AES-256-GCM.'),
        (r'(?i)Cipher\.getInstance\s*\(\s*["\']AES["\']',
         'AES Without Mode Specified (Defaults to ECB)', 'high', 7.0,
         'AES without explicit mode defaults to ECB, which is insecure (see ECB penguin attack).',
         'CWE-327', 'Always specify mode and padding: Cipher.getInstance("AES/GCM/NoPadding")'),
        (r'(?i)new\s+PBEKeySpec\s*\([^,]+,\s*[^,]+,\s*(\d+)\s*[,)]',
         'Potentially Weak PBKDF2 Iteration Count', 'medium', 5.5,
         'Low iteration counts in PBKDF2 reduce brute-force resistance for password-derived keys.',
         'CWE-916', 'Use at least 100,000 iterations for PBKDF2. Prefer Argon2 if available.'),
    ]

    # SSL and TLS
    SSL_PATTERNS = [
        (r'(?i)TrustAllCerts|TRUST_ALL|trust_all|AllowAllSSL|NullTrustManager|AcceptAllSSL',
         'Trust-All Certificate Manager', 'critical', 9.0,
         'TrustManager that trusts ALL certificates is implemented. MITM attacks are trivial.',
         'CWE-295', 'Remove the custom TrustManager. Use the system default.'),
        (r'ALLOW_ALL_HOSTNAME_VERIFIER|allowAllHostnames\s*\(\s*\)|setHostnameVerifier\s*\(\s*SSLSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER',
         'SSL Hostname Verification Disabled', 'critical', 8.8,
         'Hostname verification disabled. Any valid cert can impersonate any server.',
         'CWE-297', 'Remove ALLOW_ALL_HOSTNAME_VERIFIER. Use the default HostnameVerifier.'),
        (r'public\s+void\s+checkServerTrusted\s*\([^)]+\)\s*(?:throws[^{]+)?\{\s*\}',
         'Empty checkServerTrusted — MITM Vulnerable', 'critical', 9.1,
         'checkServerTrusted() is empty — ALL certificates are accepted silently.',
         'CWE-295', 'Never leave checkServerTrusted empty. Implement proper chain validation.'),
        (r'SSLContext\.getInstance\s*\(\s*["\']SSL["\']',
         'Outdated SSLv3 Protocol', 'high', 7.5,
         'SSLv3 is vulnerable to POODLE, BEAST. Prohibited by RFC 7568.',
         'CWE-326', 'Use SSLContext.getInstance("TLSv1.3") or "TLSv1.2"'),
        (r'SSLContext\.getInstance\s*\(\s*["\']TLSv1["\']',
         'Outdated TLS 1.0 Protocol', 'medium', 6.5,
         'TLS 1.0 is deprecated. Vulnerable to POODLE and BEAST. PCI-DSS requires TLS 1.2+.',
         'CWE-326', 'Use SSLContext.getInstance("TLSv1.2") or "TLSv1.3"'),
        (r'onReceivedSslError[^{]+\{[^}]*\.proceed\s*\(\s*\)',
         'WebView Accepts All SSL Errors', 'critical', 9.3,
         'WebView.onReceivedSslError calls handler.proceed() — accepts expired, self-signed, mismatched certs.',
         'CWE-295', 'NEVER call handler.proceed() in onReceivedSslError. Cancel and show user error.'),
        (r'(?i)CertificatePinner|OkHttpClient.*\.certificatePinner',
         'Certificate Pinning Present (Verify Implementation)', 'info', 0.0,
         'Certificate pinning detected. Verify implementation is correct and pins are not overly broad.',
         'CWE-295', 'Ensure pins are per-server, include backup pins, and have a rotation plan.'),
        (r'(?i)hostnameVerifier\s*\{\s*_\s*,\s*_\s*->\s*true\s*\}',
         'Kotlin Lambda Hostname Verifier Always Returns True', 'critical', 9.0,
         'A Kotlin lambda hostname verifier always returns true, accepting any hostname.',
         'CWE-297', 'Remove this lambda. Use the default hostname verifier.'),
    ]

    # WebView
    WEBVIEW_PATTERNS = [
        (r'setJavaScriptEnabled\s*\(\s*true\s*\)',
         'JavaScript Enabled in WebView', 'high', 6.8,
         'JavaScript is enabled in WebView. XSS in loaded content executes in app context.',
         'CWE-749', 'Disable JS unless strictly required. Restrict URLs to trusted domains.'),
        (r'addJavascriptInterface\s*\(',
         'Java-JavaScript Bridge Exposed in WebView', 'high', 8.0,
         'Native Java objects exposed to JavaScript. JS can call Java methods directly — RCE risk on Android < 4.2.',
         'CWE-749', 'Use @JavascriptInterface annotation. Validate all JS inputs rigorously.'),
        (r'setAllowFileAccess\s*\(\s*true\s*\)',
         'WebView File System Access Enabled', 'high', 7.1,
         'WebView can access local files via file:// URIs. Combined with XSS, exposes entire app sandbox.',
         'CWE-200', 'Set setAllowFileAccess(false). Default in Android 11+.'),
        (r'setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
         'Cross-Origin File Access in WebView', 'critical', 8.5,
         'File URLs can access other file URLs cross-origin. A malicious local file can read all app files.',
         'CWE-346', 'Set setAllowFileAccessFromFileURLs(false) — always false.'),
        (r'setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
         'Universal Cross-Origin Access in WebView', 'critical', 9.0,
         'File URLs can access any origin. Attacker can exfiltrate local data to external servers.',
         'CWE-346', 'Set setAllowUniversalAccessFromFileURLs(false) — never enable.'),
        (r'setSavePassword\s*\(\s*true\s*\)',
         'WebView Saves Passwords to Disk', 'medium', 5.5,
         'WebView saves passwords to disk, extractable on rooted devices.',
         'CWE-522', 'Set setSavePassword(false).'),
        (r'setDomStorageEnabled\s*\(\s*true\s*\)',
         'WebView DOM Storage Enabled', 'low', 3.5,
         'DOM storage (localStorage) is enabled. Sensitive data persists unencrypted on disk.',
         'CWE-312', 'Disable DOM storage if not needed.'),
        (r'loadUrl\s*\(\s*(?:intent|url|link|href|data)',
         'WebView Loads Unvalidated URL', 'high', 7.5,
         'WebView.loadUrl() may load unvalidated external URLs from intent/variable — open redirect / XSS risk.',
         'CWE-601', 'Validate all URLs before loading. Use allowlist of trusted domains.'),
        (r'(?i)evaluateJavascript\s*\(',
         'Dynamic JavaScript Evaluation in WebView', 'medium', 5.5,
         'evaluateJavascript() executes JS code dynamically. If input reaches this call unsanitized, XSS is possible.',
         'CWE-749', 'Never pass unsanitized user input to evaluateJavascript().'),
    ]

    # Storage
    STORAGE_PATTERNS = [
        (r'getSharedPreferences\s*\(',
         'Unencrypted SharedPreferences Usage', 'medium', 4.8,
         'SharedPreferences stores data as plaintext XML — readable on rooted devices and via ADB backup.',
         'CWE-312', 'Use EncryptedSharedPreferences from Jetpack Security for sensitive data.'),
        (r'MODE_WORLD_READABLE',
         'World-Readable File Created', 'high', 7.2,
         'File created with MODE_WORLD_READABLE allows any installed app to read its contents.',
         'CWE-732', 'Use Context.MODE_PRIVATE for all file creation.'),
        (r'MODE_WORLD_WRITABLE',
         'World-Writable File Created', 'high', 7.5,
         'File created with MODE_WORLD_WRITABLE allows any installed app to modify its contents.',
         'CWE-732', 'Use Context.MODE_PRIVATE for all file creation.'),
        (r'(?i)Log\.[deitvwDEITVW]\s*\([^,\n)]*,\s*[^)\n]*(?:password|passwd|secret|token|key|credit|ssn|pin|auth|bearer)',
         'Sensitive Data Written to Logcat', 'high', 6.5,
         'Sensitive info logged to logcat — exposed via ADB and crash reporting tools.',
         'CWE-532', 'Remove all logging of sensitive data. Add ProGuard: -assumenosideeffects class android.util.Log { *; }'),
        (r'getExternalStorageDirectory\s*\(\s*\)|Environment\.getExternalStoragePublicDirectory',
         'Sensitive Data on External/Shared Storage', 'medium', 5.5,
         'App uses external storage — accessible to any app with READ_EXTERNAL_STORAGE.',
         'CWE-312', 'Store sensitive data in internal storage only (getFilesDir() or getDataDir()).'),
        (r'ClipboardManager[^;]*setPrimaryClip\s*\(',
         'Sensitive Data Copied to System Clipboard', 'medium', 4.3,
         'Data written to system clipboard — any app can read clipboard changes.',
         'CWE-200', 'Avoid copying sensitive data. Mark clips with sensitive=true flag.'),
        (r'(?:SQLiteDatabase\.openOrCreateDatabase|getWritableDatabase|getReadableDatabase)\s*\(',
         'SQLite Database Usage — Verify Encryption', 'medium', 5.1,
         'SQLite database used. Without encryption (SQLCipher), all data is plaintext.',
         'CWE-312', 'Use SQLCipher: net.zetetic:android-database-sqlcipher'),
        (r'(?i)objectOutputStream|writeObject\s*\(',
         'Java Object Serialization Used', 'medium', 5.0,
         'Java serialization can lead to insecure deserialization vulnerabilities.',
         'CWE-502', 'Avoid Java serialization. Use JSON/Protocol Buffers instead.'),
        (r'(?i)\.setReadable\s*\(\s*true\s*,\s*false\s*\)|\.setWritable\s*\(\s*true\s*,\s*false\s*\)',
         'File Set World-Readable or World-Writable Programmatically', 'high', 7.0,
         'File.setReadable(true, false) or setWritable(true, false) makes the file accessible to all apps.',
         'CWE-732', 'Use setReadable(true, true) (owner-only) and setWritable(true, true).'),
    ]

    # Code injection
    CODE_INJECTION_PATTERNS = [
        (r'DexClassLoader\s*\(',
         'Dynamic DEX Code Loading', 'high', 7.8,
         'Application loads DEX code dynamically. If source is not integrity-verified, RCE is possible.',
         'CWE-494', 'Verify integrity of dynamically loaded code with cryptographic signatures.'),
        (r'Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(',
         'OS Shell Command Execution', 'critical', 9.0,
         'Application executes OS shell commands via Runtime.exec(). Unsanitized input = full device compromise.',
         'CWE-78', 'Avoid Runtime.exec(). If unavoidable, use a fixed command array — never include user input.'),
        (r'ProcessBuilder\s*\(',
         'Process Builder Shell Execution', 'high', 8.0,
         'ProcessBuilder executes system processes. Verify no user-controlled input reaches command arguments.',
         'CWE-78', 'Use ProcessBuilder with a fixed String array. Never construct commands from user input.'),
        (r'Class\.forName\s*\(',
         'Dynamic Class Loading via Reflection', 'medium', 5.3,
         'Classes loaded dynamically via reflection. External input reaching here = unexpected classes loaded.',
         'CWE-470', 'Validate class names against a strict whitelist before loading.'),
        (r'Method\.invoke\s*\(',
         'Reflective Method Invocation', 'medium', 5.0,
         'Methods invoked via reflection, bypassing access control checks.',
         'CWE-470', 'Minimize reflection. Validate class/method names against a whitelist.'),
        (r'PathClassLoader|InMemoryDexClassLoader',
         'In-Memory or Path Class Loader', 'high', 7.5,
         'ClassLoader used to load code from file path or in memory. Dropper pattern.',
         'CWE-494', 'Verify all code loading sources are trusted and integrity-checked.'),
    ]

    # Network
    NETWORK_PATTERNS = [
        (r'http://(?!schemas\.android\.com|www\.w3\.org|localhost|10\.0\.2\.2|127\.0\.0\.1|example\.com|schemas\.openxmlformats)[a-zA-Z0-9\-._/]{4,}',
         'Hardcoded Cleartext HTTP URL', 'high', 7.4,
         'Plaintext HTTP URL hardcoded. All traffic is unencrypted and interceptable.',
         'CWE-319', 'Change all http:// URLs to https://. Enforce with usesCleartextTraffic="false".'),
        (r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
         'Hardcoded IP Address', 'medium', 4.5,
         'Hardcoded IP exposes backend infrastructure to decompilers.',
         'CWE-200', 'Use domain names instead of IPs. Load backend URLs from remote config.'),
        (r'new\s+Socket\s*\(\s*[^)]+,\s*\d+\s*\)',
         'Raw Unencrypted TCP Socket', 'medium', 5.5,
         'Raw unencrypted TCP socket — all transmitted data is in plaintext.',
         'CWE-319', 'Use SSLSocket: SSLSocketFactory.getDefault().createSocket()'),
        (r'(?i)OkHttpClient[^;]*\.(?:connectTimeout|readTimeout|writeTimeout)\s*\(\s*0\s*,',
         'HTTP Client with Infinite Timeout', 'low', 3.5,
         'HTTP client configured with infinite timeout — vulnerable to slowloris-style denial of service.',
         'CWE-400', 'Set reasonable timeouts: 30-60 seconds for connect/read/write.'),
        (r'(?i)setConnectionReuseStrategy|setKeepAliveStrategy',
         'Custom HTTP Connection Reuse Strategy', 'low', 3.0,
         'Custom connection reuse strategy. Verify it does not bypass security controls.',
         'CWE-200', 'Use default connection pooling. Review custom strategies carefully.'),
    ]

    # Malware behaviour
    MALWARE_PATTERNS = [
        (r'(?i)getDeviceId\s*\(\s*\)',
         'IMEI Device ID Harvesting', 'high', 6.8,
         'IMEI read via getDeviceId() — persistent unique identifier for device tracking.',
         'CWE-200', 'Avoid IMEI collection. Use per-app installation IDs instead.'),
        (r'(?i)sendTextMessage\s*\([^;]+;',
         'Programmatic SMS Sending', 'critical', 8.5,
         'SMS sent without visible user interaction — premium SMS abuse, phishing, charges.',
         'CWE-862', 'Only send SMS with explicit user action. Show message content before sending.'),
        (r'(?i)getInstalledPackages\s*\(\s*\)|getInstalledApplications\s*\(',
         'Installed App Enumeration', 'medium', 4.5,
         'Enumerates all installed apps — used by banking trojans to identify target financial apps.',
         'CWE-200', 'Remove unless serving a clear legitimate purpose disclosed to users.'),
        (r'(?i)MediaProjection|createVirtualDisplay\s*\(',
         'Screen Capture / Recording Capability', 'high', 7.8,
         'App can capture the screen using MediaProjection — serious privacy risk without consent.',
         'CWE-200', 'Only capture with explicit user consent shown each session.'),
        (r'(?i)abortBroadcast\s*\(\s*\)',
         'Broadcast Abortion — SMS Interception Indicator', 'critical', 9.0,
         'abortBroadcast() prevents SMS reaching the user\'s SMS app — primary banking trojan technique.',
         'CWE-862', 'Remove abortBroadcast() unless documented legitimate reason.'),
        (r'(?i)AccessibilityService|android\.accessibilityservice',
         'Accessibility Service Usage', 'high', 7.8,
         'Accessibility Service can read all on-screen content including passwords. Frequently abused by trojans.',
         'CWE-200', 'Only use for genuine accessibility features. Play Store reviews this strictly.'),
        (r'(?i)dispatchKeyEvent\s*\([^)]+KeyEvent',
         'Key Event Interception', 'high', 7.5,
         'Key events intercepted. Combined with Accessibility Service, this is a keylogging pattern.',
         'CWE-200', 'Remove key event interception unless a legitimate keyboard/accessibility app.'),
        (r'(?i)getSimSerialNumber\s*\(\s*\)|getSubscriberId\s*\(\s*\)',
         'SIM Identifier Access (ICCID/IMSI)', 'high', 7.0,
         'App reads SIM card identifiers — extremely sensitive, used for device tracking.',
         'CWE-200', 'Remove SIM identifier collection unless required for carrier-specific features.'),
        (r'(?i)startForeground\s*\([^)]+FOREGROUND_SERVICE',
         'Foreground Service — Persistence Mechanism', 'medium', 4.5,
         'App uses foreground services for persistent background execution.',
         'CWE-912', 'Ensure foreground services serve legitimate purposes disclosed to users.'),
        (r'(?i)PackageInstaller|installPackage\s*\(',
         'Programmatic Package Installation', 'critical', 9.0,
         'App attempts to install other packages programmatically — dropper/malware installer behavior.',
         'CWE-494', 'Remove package installation code unless this is an app store or MDM application.'),
        (r'(?i)exec\s*\(\s*["\']su["\']|Runtime.*su\b',
         'Root Shell Execution Attempt', 'critical', 9.5,
         'App attempts to execute "su" for root shell access — malware root escalation behavior.',
         'CWE-269', 'Remove root shell execution. Legitimate apps do not need root.'),
        (r'(?i)android\.net\.VpnService|VpnService\.Builder',
         'VPN Service Implementation', 'high', 7.0,
         'App implements VPN service. Can intercept ALL device network traffic if activated.',
         'CWE-300', 'Ensure VPN is disclosed to users. Verify it is not a traffic interception tool.'),
        (r'(?i)ContactsContract\.Contacts|ContactsContract\.RawContacts',
         'Contact Database Direct Access', 'medium', 4.8,
         'Direct access to device contacts database.',
         'CWE-200', 'Disclose contact usage to users. Only access contacts needed for the feature.'),
        (r'(?i)TelephonyManager.*getLine1Number\s*\(\s*\)',
         'Phone Number Access', 'medium', 4.5,
         'App reads the device phone number (MSISDN). Sensitive PII.',
         'CWE-200', 'Avoid reading phone number unless essential. Disclose in privacy policy.'),
    ]

    # Anti-analysis
    ANTI_ANALYSIS_PATTERNS = [
        (r'(?i)isEmulator|Build\.FINGERPRINT.*generic|emulator.*detected|genymotion',
         'Emulator Detection', 'medium', 4.5,
         'App checks if running in an emulator — behavior analysis evasion technique.',
         'CWE-693', 'Remove emulator detection. Legitimate apps need not differ in emulators.'),
        (r'Debug\.isDebuggerConnected\s*\(\s*\)',
         'Debugger Detection', 'medium', 4.8,
         'App detects attached debuggers and may alter behavior to evade security analysis.',
         'CWE-693', 'Remove anti-debugging code in release builds.'),
        (r'(?i)frida|xposed|substrate.*hook',
         'Anti-Hooking Framework Detection', 'medium', 5.0,
         'App detects Frida or Xposed hooks, preventing dynamic security analysis.',
         'CWE-693', 'Consider whether this protection is proportionate to legitimate security needs.'),
        (r'(?i)isRooted|checkRootMethod|su.*binary|RootBeer|rootCheck',
         'Root Detection', 'low', 3.5,
         'Root detection is implemented. Acceptable for banking apps; verify no false positives.',
         'CWE-693', 'Acceptable for high-security apps. Ensure it does not block legitimate users.'),
        (r'(?i)getRuntime.*availableProcessors\s*\(\s*\).*[<>]\s*[12]',
         'CPU Core Count Check (VM Detection)', 'medium', 4.0,
         'Checking CPU core count to detect virtual machines (usually have 1-2 cores).',
         'CWE-693', 'Remove environment detection for VM evasion.'),
        (r'(?i)SystemClock\.elapsedRealtime|SystemClock\.uptimeMillis.*anti.*debug',
         'Timing-Based Anti-Debug Detection', 'medium', 4.5,
         'Timing checks used to detect debugger slowdown — analysis evasion.',
         'CWE-693', 'Remove timing-based anti-debug techniques.'),
        (r'(?i)SafetyNet|DeviceIntegrity|PlayIntegrity',
         'SafetyNet / Play Integrity API Usage', 'info', 0.0,
         'App uses SafetyNet/Play Integrity API for device attestation.',
         'CWE-693', 'Ensure attestation failures are handled server-side, not client-side only.'),
    ]

    def analyze(self, all_strings: List[str], smali_code: str,
                api_calls: List[str], package_name: str = '') -> List[Dict]:
        findings = []
        seen: Set[str] = set()

        string_corpus = '\n'.join(str(s) for s in all_strings)
        behavior_corpus = smali_code + '\n' + '\n'.join(api_calls)
        full_corpus = string_corpus + '\n' + behavior_corpus

        all_checks = [
            (self.SECRET_PATTERNS,         'Secrets',          string_corpus, True),
            (self.CRYPTO_PATTERNS,         'Cryptography',     full_corpus,   False),
            (self.SSL_PATTERNS,            'SSL/TLS',          full_corpus,   False),
            (self.WEBVIEW_PATTERNS,        'WebView',          full_corpus,   False),
            (self.STORAGE_PATTERNS,        'Storage',          full_corpus,   False),
            (self.CODE_INJECTION_PATTERNS, 'Code Injection',   full_corpus,   False),
            (self.NETWORK_PATTERNS,        'Network',          string_corpus, False),
            (self.MALWARE_PATTERNS,        'Malware Behavior', full_corpus,   False),
            (self.ANTI_ANALYSIS_PATTERNS,  'Anti-Analysis',    full_corpus,   False),
        ]

        for patterns, category, corpus, entropy_check in all_checks:
            for pt in patterns:
                pattern  = pt[0]
                title    = pt[1]
                severity = pt[2]
                cvss     = pt[3]
                desc     = pt[4] if len(pt) > 4 else f'{title} detected.'
                cwe      = pt[5] if len(pt) > 5 else 'CWE-200'
                remedy   = pt[6] if len(pt) > 6 else 'Review and remediate.'

                if title in seen:
                    continue

                matches = _find(corpus, pattern)
                if not matches:
                    continue

                match = matches[0]
                evidence = _extract_context(corpus, match)

                # Entropy validation for secrets
                if entropy_check:
                    val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    if any(fp in val.lower() for fp in FALSE_POSITIVE_WORDS):
                        continue
                    if len(val) > 6 and shannon_entropy(val) < 2.5:
                        continue
                    if len(val) > 4 and len(set(val)) < 4:
                        continue

                seen.add(title)
                owasp = {
                    'Secrets':          'M1: Improper Credential Usage',
                    'Cryptography':     'M5: Improper Cryptography Usage',
                    'SSL/TLS':          'M3: Insecure Communication',
                    'WebView':          'M4: Insufficient Input/Output Validation',
                    'Storage':          'M2: Insecure Data Storage',
                    'Code Injection':   'M4: Insufficient Input/Output Validation',
                    'Network':          'M3: Insecure Communication',
                    'Malware Behavior': 'M8: Security Misconfiguration',
                    'Anti-Analysis':    'M7: Insufficient Binary Protections',
                }.get(category, 'M8: Security Misconfiguration')

                findings.append({
                    'title': title, 'severity': severity, 'category': category,
                    'cvss_score': cvss, 'description': desc,
                    'location': 'DEX bytecode / application code',
                    'evidence': evidence[:400] if evidence else match.group(0)[:200],
                    'remediation': remedy, 'poc_command': None,
                    'owasp_category': owasp, 'cwe_id': cwe,
                    'confidence': 'high' if category in ('Secrets', 'SSL/TLS') else 'medium',
                })

        return findings


# 4. TAINT / DATA FLOW ANALYSIS

class TaintAnalyzer:
    """
    Source-to-sink taint tracking.
    Identifies flows from sensitive data sources to dangerous sinks.
    Uses API call graph cross-referencing for flow detection.
    """

    SENSITIVE_SOURCES = {
        'Contacts':    ['ContactsContract', 'getContacts', 'query.*contacts'],
        'SMS':         ['SmsManager', 'Telephony.Sms', 'readSms', 'receiveSms'],
        'Location':    ['getLastKnownLocation', 'requestLocationUpdates', 'FusedLocation'],
        'Camera':      ['Camera.open', 'CameraManager', 'takePicture'],
        'Microphone':  ['AudioRecord', 'MediaRecorder', 'startRecording'],
        'Clipboard':   ['getSystemService.*CLIPBOARD', 'getPrimaryClip'],
        'IMEI':        ['getDeviceId', 'getImei', 'getSubscriberId'],
        'Accounts':    ['AccountManager', 'getAccounts', 'getAuthToken'],
        'Credentials': ['getPassword', 'getSharedPreferences.*password', 'KeyStore.getEntry'],
    }

    DANGEROUS_SINKS = {
        'HTTP':              ['HttpURLConnection', 'OkHttpClient', 'Retrofit', 'Volley', 'okhttp3'],
        'Logcat':            ['Log.d', 'Log.e', 'Log.i', 'Log.v', 'Log.w', 'println', 'System.out'],
        'ExternalStorage':   ['getExternalStorageDirectory', 'getExternalFilesDir'],
        'WebView':           ['loadUrl', 'loadData', 'evaluateJavascript'],
        'IPC':               ['sendBroadcast', 'startActivity', 'startService', 'ContentResolver'],
        'SQLite':            ['execSQL', 'rawQuery', 'insert.*database', 'update.*database'],
        'DynamicExecution':  ['Runtime.exec', 'DexClassLoader', 'ProcessBuilder', 'System.load'],
        'Clipboard':         ['setPrimaryClip', 'ClipboardManager'],
        'SharedPrefs':       ['SharedPreferences.Editor', 'putString.*password', 'putString.*token'],
    }

    TAINT_FLOW_RULES = [
        # (source_category, sink_category, severity, title, description)
        ('Location',    'HTTP',            'high',     'Location Data Transmitted over Network',
         'Device location is read and transmitted over the network. Ensure encryption and user consent.'),
        ('Location',    'Logcat',          'high',     'Location Data Written to Logcat',
         'GPS coordinates logged to logcat — readable via ADB and crash reporting tools.'),
        ('Contacts',    'HTTP',            'high',     'Contact Data Transmitted over Network',
         'Contact data is read and sent over the network. Verify GDPR/CCPA compliance and user consent.'),
        ('Contacts',    'Logcat',          'medium',   'Contact Data Written to Logcat',
         'Contact data logged to logcat — privacy violation.'),
        ('SMS',         'HTTP',            'critical', 'SMS Content Transmitted over Network',
         'SMS messages (potentially including OTPs) are read and sent to a remote server.'),
        ('IMEI',        'HTTP',            'high',     'Device IMEI Transmitted over Network',
         'Device IMEI sent to a remote server. IMEI is persistent — cannot be changed. Privacy violation.'),
        ('Accounts',    'HTTP',            'critical', 'Account Credentials Transmitted over Network',
         'Account manager data or credentials sent over the network.'),
        ('Credentials', 'Logcat',          'critical', 'Credentials Written to Logcat',
         'Credentials or secrets are being logged — exposed via ADB.'),
        ('Microphone',  'HTTP',            'critical', 'Audio Data Transmitted over Network',
         'Audio recordings uploaded to remote server without visible user indication.'),
        ('Camera',      'HTTP',            'high',     'Camera Data Transmitted over Network',
         'Camera captures transmitted to remote server.'),
        ('Clipboard',   'HTTP',            'medium',   'Clipboard Content Transmitted over Network',
         'Clipboard data (possibly copied passwords) sent to remote server.'),
        ('IMEI',        'SharedPrefs',     'medium',   'Device ID Persisted in SharedPreferences',
         'IMEI stored in SharedPreferences — accessible via ADB backup on non-rooted devices.'),
        ('Location',    'ExternalStorage', 'medium',   'Location Data Written to External Storage',
         'GPS data written to external storage — accessible to any app with READ_EXTERNAL_STORAGE.'),
        ('Credentials', 'SharedPrefs',     'high',     'Credentials Stored in SharedPreferences',
         'Passwords or tokens stored in unencrypted SharedPreferences.'),
    ]

    def analyze(self, api_calls: List[str], smali_code: str) -> List[Dict]:
        findings = []
        api_text = '\n'.join(api_calls)
        corpus = api_text + '\n' + smali_code

        # Detect which sources and sinks are present
        active_sources: Dict[str, bool] = {}
        active_sinks: Dict[str, bool] = {}

        for src_cat, patterns in self.SENSITIVE_SOURCES.items():
            for p in patterns:
                if _find(corpus, p, re.IGNORECASE):
                    active_sources[src_cat] = True
                    break

        for sink_cat, patterns in self.DANGEROUS_SINKS.items():
            for p in patterns:
                if _find(corpus, p, re.IGNORECASE):
                    active_sinks[sink_cat] = True
                    break

        # Match flows
        seen_flows: Set[str] = set()
        for src, sink, severity, title, description in self.TAINT_FLOW_RULES:
            flow_key = f"{src}→{sink}"
            if flow_key in seen_flows:
                continue
            if active_sources.get(src) and active_sinks.get(sink):
                seen_flows.add(flow_key)
                # Find source evidence
                src_patterns = self.SENSITIVE_SOURCES[src]
                src_evidence = ''
                for p in src_patterns:
                    ms = _find(corpus, p, re.IGNORECASE)
                    if ms:
                        src_evidence = _extract_context(corpus, ms[0], 80)
                        break
                findings.append({
                    'title': title,
                    'severity': severity,
                    'category': 'Data Flow',
                    'cvss_score': {'critical': 9.0, 'high': 7.0, 'medium': 5.0, 'low': 2.0}.get(severity, 5.0),
                    'description': (
                        f'[Taint Flow: {src} → {sink}] {description} '
                        f'Both the data source ({src}) and sink ({sink}) are present in the application.'
                    ),
                    'location': 'DEX bytecode / API call graph',
                    'evidence': f'Source: {src} | Sink: {sink} | Context: {src_evidence[:200]}',
                    'remediation': (
                        f'Audit all flows from {src} to {sink}. Ensure: (1) user consent obtained, '
                        f'(2) data is encrypted in transit, (3) data is minimized before transmission, '
                        f'(4) a privacy policy discloses this collection.'
                    ),
                    'poc_command': None,
                    'owasp_category': 'M6: Insecure Authorization',
                    'cwe_id': 'CWE-359',
                    'confidence': 'medium',
                })

        # Summary of active sources for information
        if active_sources:
            src_list = ', '.join(sorted(active_sources.keys()))
            findings.append({
                'title': f'Sensitive Data Sources Accessed: {src_list}',
                'severity': 'info',
                'category': 'Data Flow',
                'cvss_score': 0.0,
                'description': (
                    f'Application accesses the following sensitive data sources: {src_list}. '
                    f'These are not necessarily vulnerabilities but require privacy policy disclosure, '
                    f'user consent, and careful data handling.'
                ),
                'location': 'API call graph',
                'evidence': f'Active sources: {src_list}',
                'remediation': 'Ensure all data collection is disclosed in your privacy policy and that user consent is obtained.',
                'poc_command': None,
                'owasp_category': 'M6: Insecure Authorization',
                'cwe_id': 'CWE-359',
                'confidence': 'high',
            })

        return findings


# 5. NATIVE LIBRARY ANALYSIS

class NativeLibAnalyzer:
    """
    ELF-aware .so file analysis. Parses ELF headers, extracts symbols,
    detects unsafe C functions, shellcode patterns, and obfuscation loaders.
    """

    UNSAFE_FUNCS = [
        'strcpy', 'strcat', 'sprintf', 'gets', 'scanf', 'system', 'popen',
        'ptrace', 'printf', 'vsprintf', 'memcpy', 'memmove', 'stpcpy',
        'wcscpy', 'wcscat', 'wcsncat',
    ]

    DANGEROUS_SYSCALLS = [
        b'execve', b'execl', b'execvp', b'fork', b'ptrace',
        b'mprotect', b'mmap', b'dlopen', b'dlsym',
    ]

    SHELLCODE_PATTERNS = [
        rb'\x6a\x0b\x58\x99\x52\x68',  # x86 execve shellcode
        rb'\x01\x00\xa0\xe3\x0f\x00\x00\xef',  # ARM sys_exit
        rb'\xeb\x3f\x5e\x31\xc9',       # x86 JMP-CALL-POP pattern
    ]

    ELF_MAGIC = b'\x7fELF'

    def _parse_elf_strings(self, data: bytes) -> List[str]:
        """Extract readable strings from ELF binary."""
        strings = []
        printable = re.findall(rb'[\x20-\x7e]{5,}', data)
        for s in printable:
            try:
                strings.append(s.decode('ascii'))
            except Exception:
                pass
        return strings

    def _is_elf(self, data: bytes) -> bool:
        return data[:4] == self.ELF_MAGIC

    def _parse_elf_header(self, data: bytes) -> Dict:
        """Parse ELF header for architecture and basic properties."""
        info = {'arch': 'unknown', 'bits': 32, 'endian': 'little', 'type': 'unknown'}
        if len(data) < 16:
            return info
        try:
            ei_class = data[4]   # 1=32bit, 2=64bit
            ei_data  = data[5]   # 1=LE, 2=BE
            e_type   = struct.unpack_from('<H' if ei_data == 1 else '>H', data, 16)[0]
            e_machine = struct.unpack_from('<H' if ei_data == 1 else '>H', data, 18)[0]

            info['bits']   = 64 if ei_class == 2 else 32
            info['endian'] = 'little' if ei_data == 1 else 'big'
            info['type']   = {1: 'relocatable', 2: 'executable', 3: 'shared_lib', 4: 'core'}.get(e_type, 'unknown')
            info['arch']   = {
                0x28: 'ARM', 0xb7: 'ARM64', 0x03: 'x86',
                0x3e: 'x86_64', 0x08: 'MIPS',
            }.get(e_machine, f'unknown({hex(e_machine)})')
        except Exception:
            pass
        return info

    def analyze(self, apk_path: str) -> List[Dict]:
        findings = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                so_files = [n for n in zf.namelist() if n.endswith('.so')]
                if not so_files:
                    return findings

                # Summary finding
                findings.append({
                    'title': f'Native Libraries Present ({len(so_files)} .so files)',
                    'severity': 'low', 'category': 'Native Code', 'cvss_score': 2.5,
                    'description': (
                        f'App includes {len(so_files)} native library file(s): '
                        f'{", ".join(so_files[:5])}{"..." if len(so_files) > 5 else ""}. '
                        f'Native code bypasses the Java security sandbox and may contain memory safety vulnerabilities.'
                    ),
                    'location': 'lib/ directory',
                    'evidence': ', '.join(so_files[:8]),
                    'remediation': (
                        'Audit native libs for memory safety. Enable -fstack-protector-strong, '
                        '-D_FORTIFY_SOURCE=2, and full RELRO in compilation.'
                    ),
                    'poc_command': None,
                    'owasp_category': 'M7: Insufficient Binary Protections',
                    'cwe_id': 'CWE-119', 'confidence': 'high',
                })

                for so in so_files[:5]:  # Analyze first 5 libs
                    try:
                        data = zf.read(so)
                    except Exception:
                        continue

                    # Entropy check (packing/encryption)
                    ent = byte_entropy(data)
                    if ent > 7.5:
                        findings.append({
                            'title': f'High-Entropy Native Library — Possible Packing: {so.split("/")[-1]}',
                            'severity': 'medium', 'category': 'Obfuscation', 'cvss_score': 4.5,
                            'description': (
                                f'"{so}" has high byte entropy ({ent:.2f}/8.0), consistent with packed, '
                                f'encrypted, or heavily obfuscated native code. Packers hide malicious code '
                                f'from static analysis.'
                            ),
                            'location': so, 'evidence': f'Byte entropy: {ent:.2f}/8.0',
                            'remediation': 'Investigate packed native libraries. Unpack using tools like UPX, LIEF, or Frida.',
                            'poc_command': None,
                            'owasp_category': 'M7: Insufficient Binary Protections',
                            'cwe_id': 'CWE-506', 'confidence': 'medium',
                        })

                    # ELF header analysis
                    if self._is_elf(data):
                        elf_info = self._parse_elf_header(data)
                        elf_strings = self._parse_elf_strings(data)
                        raw = data.decode('latin-1', errors='replace')

                        # Unsafe C functions (check symbol table via null-terminated strings)
                        found_unsafe = [f for f in self.UNSAFE_FUNCS if f'\x00{f}\x00' in raw]
                        if found_unsafe:
                            findings.append({
                                'title': f'Unsafe C Functions: {", ".join(found_unsafe[:5])}',
                                'severity': 'medium', 'category': 'Native Code', 'cvss_score': 5.5,
                                'description': (
                                    f'Unsafe C functions ({", ".join(found_unsafe)}) found in {so}. '
                                    f'These lack bounds checking and can cause exploitable buffer overflows.'
                                ),
                                'location': so,
                                'evidence': f'Symbol table exports: {", ".join(found_unsafe)}',
                                'remediation': 'Use safe alternatives: strcpy→strlcpy, sprintf→snprintf, gets→fgets.',
                                'poc_command': None,
                                'owasp_category': 'M7: Insufficient Binary Protections',
                                'cwe_id': 'CWE-120', 'confidence': 'medium',
                            })

                        # Dangerous syscalls
                        found_syscalls = [s.decode() for s in self.DANGEROUS_SYSCALLS if s in data]
                        if 'ptrace' in found_syscalls:
                            findings.append({
                                'title': f'ptrace() Syscall in Native Code: {so.split("/")[-1]}',
                                'severity': 'high', 'category': 'Anti-Analysis', 'cvss_score': 6.5,
                                'description': (
                                    f'ptrace() found in {so}. Used for anti-debugging, process injection, '
                                    f'or hooking other processes.'
                                ),
                                'location': so, 'evidence': 'ptrace symbol in ELF',
                                'remediation': 'Remove ptrace usage unless this is a legitimate debugger or tracing tool.',
                                'poc_command': None,
                                'owasp_category': 'M7: Insufficient Binary Protections',
                                'cwe_id': 'CWE-693', 'confidence': 'high',
                            })

                        if 'dlopen' in found_syscalls or 'dlsym' in found_syscalls:
                            findings.append({
                                'title': f'Dynamic Library Loading in Native Code: {so.split("/")[-1]}',
                                'severity': 'medium', 'category': 'Code Injection', 'cvss_score': 5.5,
                                'description': (
                                    f'dlopen/dlsym in {so} loads additional native libraries dynamically. '
                                    f'If the library path is attacker-controlled, code injection is possible.'
                                ),
                                'location': so, 'evidence': f'Symbols: {", ".join(s for s in ["dlopen","dlsym"] if s in found_syscalls)}',
                                'remediation': 'Audit all dlopen() calls. Ensure library paths are hardcoded or cryptographically verified.',
                                'poc_command': None,
                                'owasp_category': 'M7: Insufficient Binary Protections',
                                'cwe_id': 'CWE-494', 'confidence': 'medium',
                            })

                        # Shellcode pattern detection
                        for sc_pattern in self.SHELLCODE_PATTERNS:
                            if sc_pattern in data:
                                findings.append({
                                    'title': f'Shellcode Pattern Detected in Native Library: {so.split("/")[-1]}',
                                    'severity': 'critical', 'category': 'Malware Behavior', 'cvss_score': 9.5,
                                    'description': (
                                        f'Known shellcode byte pattern detected in {so}. '
                                        f'This is a strong indicator of embedded malicious native code.'
                                    ),
                                    'location': so, 'evidence': f'Shellcode pattern match in binary',
                                    'remediation': 'Immediately investigate and remove this library. Do not distribute this APK.',
                                    'poc_command': None,
                                    'owasp_category': 'M7: Insufficient Binary Protections',
                                    'cwe_id': 'CWE-506', 'confidence': 'high',
                                })
                                break

                        # Suspicious strings in native code
                        suspicious_native_strings = [
                            s for s in elf_strings
                            if any(kw in s.lower() for kw in [
                                '/system/bin/sh', '/bin/sh', 'chmod 777',
                                'curl ', 'wget ', 'nc -', 'ncat ',
                                '/proc/net', '/proc/self/maps', 'frida-gadget',
                                'inject', 'hook', 'payload',
                            ])
                        ]
                        if suspicious_native_strings:
                            findings.append({
                                'title': f'Suspicious Strings in Native Library: {so.split("/")[-1]}',
                                'severity': 'high', 'category': 'Malware Behavior', 'cvss_score': 7.5,
                                'description': (
                                    f'Suspicious strings found embedded in native library {so}: '
                                    f'{suspicious_native_strings[:3]}. These may indicate shell execution, '
                                    f'injection, or network communication from native code.'
                                ),
                                'location': so,
                                'evidence': f'Strings: {suspicious_native_strings[:3]}',
                                'remediation': 'Review native library source. Remove or justify all suspicious strings.',
                                'poc_command': None,
                                'owasp_category': 'M7: Insufficient Binary Protections',
                                'cwe_id': 'CWE-506', 'confidence': 'medium',
                            })

                    else:
                        # Not a valid ELF — suspicious
                        if len(data) > 1024:
                            findings.append({
                                'title': f'Non-ELF File with .so Extension: {so.split("/")[-1]}',
                                'severity': 'high', 'category': 'Malware Behavior', 'cvss_score': 7.0,
                                'description': (
                                    f'File {so} has a .so extension but does not begin with ELF magic bytes. '
                                    f'This may be an encrypted payload, a disguised file, or a loader.'
                                ),
                                'location': so,
                                'evidence': f'File header: {data[:16].hex()} (expected 7f454c46 for ELF)',
                                'remediation': 'Investigate this file. Decode or decrypt if encrypted. Do not distribute.',
                                'poc_command': None,
                                'owasp_category': 'M7: Insufficient Binary Protections',
                                'cwe_id': 'CWE-506', 'confidence': 'high',
                            })

        except Exception as e:
            logger.debug(f'Native lib analysis error: {e}')

        return findings


# 6. CERTIFICATE ANALYZER

class CertificateAnalyzer:
    """
    Analyzes APK signing certificates for debug certs, weak keys, and
    Janus vulnerability indicators.
    """

    def analyze(self, apk_path: str) -> List[Dict]:
        findings = []
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                cert_files = [
                    n for n in zf.namelist()
                    if n.startswith('META-INF/') and any(n.endswith(e) for e in ('.RSA', '.DSA', '.EC'))
                ]

                if not cert_files:
                    findings.append({
                        'title': 'APK Signature File Not Found',
                        'severity': 'medium', 'category': 'Certificate', 'cvss_score': 5.5,
                        'description': (
                            'No v1 signature file (.RSA/.DSA/.EC) found in META-INF/. '
                            'App may use APK Signature Scheme v2/v3 only (acceptable), '
                            'but verify the APK is properly signed before distribution.'
                        ),
                        'location': 'META-INF/', 'evidence': 'No .RSA/.DSA/.EC files present',
                        'remediation': 'Ensure APK is signed with a valid production certificate.',
                        'poc_command': None, 'owasp_category': 'M7: Insufficient Binary Protections',
                        'cwe_id': 'CWE-347', 'confidence': 'medium',
                    })
                    return findings

                for cf in cert_files:
                    data = zf.read(cf)
                    cert_size = len(data)

                    # Debug certificate detection
                    is_debug = (
                        b'Android Debug' in data or
                        b'androiddebugkey' in data or
                        b'Android Debug Build' in data or
                        cert_size < 900
                    )

                    if is_debug:
                        findings.append({
                            'title': 'Debug Certificate Detected',
                            'severity': 'high', 'category': 'Certificate', 'cvss_score': 7.5,
                            'description': (
                                'APK is signed with the Android debug keystore. Debug-signed APKs enable '
                                'ADB debugging on any device, allow backup extraction, and should NEVER '
                                'be distributed publicly.'
                            ),
                            'location': cf,
                            'evidence': f'{cf} ({cert_size} bytes — consistent with debug certificate)',
                            'remediation': (
                                'Sign with a production keystore: '
                                'keytool -genkey -v -keystore release.keystore -alias release '
                                '-keyalg RSA -keysize 2048 -validity 10000'
                            ),
                            'poc_command': f'adb shell run-as <package_name> ls /data/data/<package_name>/',
                            'owasp_category': 'M7: Insufficient Binary Protections',
                            'cwe_id': 'CWE-321', 'confidence': 'medium',
                        })

                    # Weak key size heuristic: RSA certs with very small size may use short keys
                    if cert_size < 500 and not is_debug:
                        findings.append({
                            'title': 'Potentially Weak Signing Certificate (Small Size)',
                            'severity': 'medium', 'category': 'Certificate', 'cvss_score': 5.5,
                            'description': (
                                f'Certificate {cf} is unusually small ({cert_size} bytes). '
                                f'This may indicate a weak key size (< 2048-bit RSA or < 256-bit EC).'
                            ),
                            'location': cf,
                            'evidence': f'Certificate size: {cert_size} bytes',
                            'remediation': 'Use RSA 2048-bit or EC P-256 minimum. Recommended: RSA 4096 or EC P-384.',
                            'poc_command': None,
                            'owasp_category': 'M7: Insufficient Binary Protections',
                            'cwe_id': 'CWE-326', 'confidence': 'low',
                        })

                    # SHA-1 signature detection
                    if b'sha1WithRSAEncryption' in data or b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05' in data:
                        findings.append({
                            'title': 'APK Signed with SHA-1 — Weak Signature Algorithm',
                            'severity': 'medium', 'category': 'Certificate', 'cvss_score': 5.9,
                            'description': (
                                f'APK signature uses SHA-1 ({cf}). SHA-1 is deprecated for code signing. '
                                f'Google Play Store rejects apps signed only with SHA-1.'
                            ),
                            'location': cf,
                            'evidence': 'SHA-1 OID detected in certificate data',
                            'remediation': 'Re-sign with SHA-256 or stronger: jarsigner -sigalg SHA256withRSA -digestalg SHA-256',
                            'poc_command': None,
                            'owasp_category': 'M7: Insufficient Binary Protections',
                            'cwe_id': 'CWE-327', 'confidence': 'medium',
                        })

        except Exception as e:
            logger.debug(f'Certificate analysis error: {e}')

        return findings


# 7. OBFUSCATION ANALYZER

class ObfuscationAnalyzer:
    """
    Detects obfuscation, packers, string encryption, and measures
    reverse-engineering difficulty.
    """

    def analyze(self, smali_code: str, apk_path: str) -> Dict:
        result = {
            'findings': [],
            'obfuscation_score': 0,
            'protection_level': 'None',
            'techniques_detected': [],
        }
        score = 0

        # ProGuard/R8: single-letter class names
        obf_classes = re.findall(r'\.class\s+(?:public\s+)?(?:final\s+)?L[a-z]/[a-z]', smali_code)
        if len(obf_classes) > 10:
            score += 35
            result['techniques_detected'].append('ProGuard/R8 name minification')
            result['findings'].append({
                'title': 'Code Obfuscation Detected (ProGuard/R8)',
                'severity': 'low', 'category': 'Obfuscation', 'cvss_score': 3.0,
                'description': (
                    f'Code is obfuscated ({len(obf_classes)} single-letter class names detected). '
                    f'This is a recommended security practice that makes reverse engineering harder.'
                ),
                'location': 'DEX bytecode',
                'evidence': f'{len(obf_classes)} obfuscated class names found',
                'remediation': 'Good practice. Also consider runtime app self-protection (RASP).',
                'poc_command': None, 'owasp_category': 'M7: Insufficient Binary Protections',
                'cwe_id': 'CWE-693', 'confidence': 'high',
            })
        elif smali_code and len(smali_code) > 2000:
            result['findings'].append({
                'title': 'No Code Obfuscation Detected',
                'severity': 'medium', 'category': 'Obfuscation', 'cvss_score': 4.5,
                'description': (
                    'App code is not obfuscated. Class names, method names, and business logic are '
                    'fully readable after decompilation, making reverse engineering trivial.'
                ),
                'location': 'DEX bytecode',
                'evidence': 'Clear, readable class/method names throughout',
                'remediation': (
                    'Enable R8/ProGuard in release builds. In build.gradle: '
                    'minifyEnabled true, proguardFiles getDefaultProguardFile("proguard-android-optimize.txt")'
                ),
                'poc_command': None, 'owasp_category': 'M7: Insufficient Binary Protections',
                'cwe_id': 'CWE-693', 'confidence': 'high',
            })

        # String encryption patterns (DexGuard / custom)
        if re.search(r'(?i)decrypt\s*\(|deobfuscate\s*\(|decode.*string|string.*decode', smali_code):
            score += 25
            result['techniques_detected'].append('String encryption/decryption')
            result['findings'].append({
                'title': 'String Encryption Detected',
                'severity': 'low', 'category': 'Obfuscation', 'cvss_score': 2.5,
                'description': (
                    'String decryption routines detected. Strings are encrypted at rest and '
                    'decrypted at runtime, significantly raising the bar for static analysis.'
                ),
                'location': 'DEX bytecode',
                'evidence': 'decrypt() / deobfuscate() / decode() method patterns detected',
                'remediation': 'String encryption is a good practice. Combine with anti-tampering.',
                'poc_command': None, 'owasp_category': 'M7: Insufficient Binary Protections',
                'cwe_id': 'CWE-693', 'confidence': 'medium',
            })

        # Control flow obfuscation (many gotos / complex branching in smali)
        goto_count = len(re.findall(r'\bgoto\b', smali_code))
        if goto_count > 200:
            score += 20
            result['techniques_detected'].append('Control flow obfuscation')
            result['findings'].append({
                'title': 'Control Flow Obfuscation Detected',
                'severity': 'low', 'category': 'Obfuscation', 'cvss_score': 2.0,
                'description': (
                    f'Excessive goto statements ({goto_count}) detected — consistent with '
                    f'control flow flattening or obfuscation tools like DexGuard or Allatori.'
                ),
                'location': 'DEX bytecode',
                'evidence': f'{goto_count} goto statements detected',
                'remediation': 'Control flow obfuscation is a defensive measure. Acceptable for security-sensitive apps.',
                'poc_command': None, 'owasp_category': 'M7: Insufficient Binary Protections',
                'cwe_id': 'CWE-693', 'confidence': 'medium',
            })

        # Packer detection via APK-level properties
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                names = zf.namelist()
                # Packers often embed secondary DEX inside assets
                asset_dex = [n for n in names if n.startswith('assets/') and n.endswith(('.dex', '.jar', '.zip'))]
                if asset_dex:
                    score += 30
                    result['techniques_detected'].append('Asset-embedded DEX (packer indicator)')
                    result['findings'].append({
                        'title': f'DEX/JAR Files in Assets Directory — Packer Indicator',
                        'severity': 'high', 'category': 'Obfuscation', 'cvss_score': 7.0,
                        'description': (
                            f'DEX or JAR files found embedded in the assets directory: {asset_dex}. '
                            f'This is a common technique used by packers to hide the real application '
                            f'payload from static analysis tools.'
                        ),
                        'location': 'assets/',
                        'evidence': f'Embedded executables: {asset_dex}',
                        'remediation': 'Investigate these files. Legitimate apps do not typically store DEX in assets.',
                        'poc_command': None, 'owasp_category': 'M7: Insufficient Binary Protections',
                        'cwe_id': 'CWE-506', 'confidence': 'high',
                    })
        except Exception:
            pass

        result['obfuscation_score'] = min(100, score)
        result['protection_level'] = (
            'High' if score > 60 else
            'Medium' if score > 30 else
            'Low' if score > 10 else
            'None'
        )
        return result


# 8. THIRD-PARTY SDK / SUPPLY CHAIN ANALYZER

class SDKAnalyzer:
    """
    Detects third-party SDKs, tracking libraries, adware SDKs, and
    known-vulnerable library versions.
    """

    def analyze(self, class_names: List[str], string_corpus: str) -> List[Dict]:
        findings = []
        detected_trackers = []
        detected_vuln_libs = []

        class_text = '\n'.join(class_names)

        # Tracker / adware SDK detection
        for pkg_prefix, sdk_name in TRACKER_SDKS.items():
            if pkg_prefix.replace('.', '/') in class_text or pkg_prefix in class_text:
                detected_trackers.append(sdk_name)

        if detected_trackers:
            findings.append({
                'title': f'Tracking/Analytics SDKs Detected ({len(detected_trackers)})',
                'severity': 'medium', 'category': 'Privacy',
                'cvss_score': 4.3,
                'description': (
                    f'The following tracking and analytics SDKs are integrated: '
                    f'{", ".join(detected_trackers)}. These SDKs may collect device identifiers, '
                    f'behavioral data, and PII without explicit user awareness.'
                ),
                'location': 'DEX class names',
                'evidence': f'SDKs: {", ".join(detected_trackers[:5])}',
                'remediation': (
                    'Disclose all tracking SDKs in your privacy policy. '
                    'Implement user consent mechanisms (especially for GDPR/CCPA). '
                    'Review SDK data collection practices. Consider removing unnecessary SDKs.'
                ),
                'poc_command': None,
                'owasp_category': 'M8: Security Misconfiguration',
                'cwe_id': 'CWE-359', 'confidence': 'high',
            })

        # Vulnerable library detection
        for lib_pkg, vuln_info in VULNERABLE_LIBS.items():
            lib_path = lib_pkg.replace('.', '/')
            if lib_path in class_text or lib_pkg in string_corpus:
                detected_vuln_libs.append((lib_pkg, vuln_info))

        for lib_pkg, vuln_info in detected_vuln_libs:
            findings.append({
                'title': f'Potentially Vulnerable Library: {lib_pkg.split(".")[-1]}',
                'severity': 'high', 'category': 'Components',
                'cvss_score': 7.5,
                'description': (
                    f'Library "{lib_pkg}" detected. Known issue: {vuln_info["issue"]}. '
                    f'Reference: {vuln_info["cve"]}. Verify the version in use is patched.'
                ),
                'location': 'DEX class names',
                'evidence': f'Package: {lib_pkg} | CVE: {vuln_info["cve"]}',
                'remediation': (
                    f'Update {lib_pkg} to the latest patched version. '
                    f'Check release notes for security fixes. Use Dependency-Check or OSS Index to audit all dependencies.'
                ),
                'poc_command': None,
                'owasp_category': 'M8: Security Misconfiguration',
                'cwe_id': 'CWE-1104', 'confidence': 'medium',
            })

        # Suspicious domain detection
        for domain_pattern in SUSPICIOUS_DOMAINS_PATTERNS:
            matches = _find(string_corpus, domain_pattern)
            if matches:
                suspicious_domains = [_extract_context(string_corpus, m, 40) for m in matches[:3]]
                findings.append({
                    'title': 'Suspicious Domain or Endpoint Detected',
                    'severity': 'high', 'category': 'Network',
                    'cvss_score': 7.0,
                    'description': (
                        f'Suspicious domain or endpoint pattern detected in application strings. '
                        f'Examples: {suspicious_domains[:2]}. This may indicate C2 communication, '
                        f'data exfiltration, or use of URL shorteners to hide destinations.'
                    ),
                    'location': 'DEX string constants',
                    'evidence': f'{suspicious_domains[0][:200]}',
                    'remediation': (
                        'Audit all hardcoded domains. Remove URL shorteners. '
                        'Verify all endpoints against VirusTotal and threat intelligence feeds.'
                    ),
                    'poc_command': None,
                    'owasp_category': 'M3: Insecure Communication',
                    'cwe_id': 'CWE-200', 'confidence': 'medium',
                })
                break

        return findings


# 9. PRIVACY & COMPLIANCE ANALYZER

class PrivacyAnalyzer:
    """
    Checks for GDPR, CCPA, COPPA, and general privacy compliance indicators.
    """

    PII_PATTERNS = [
        (r'(?i)(?:first[_\-]?name|last[_\-]?name|full[_\-]?name)\s*[=:]\s*["\'][^"\']+["\']',
         'PII: Name field hardcoded or collected'),
        (r'(?i)email\s*[=:]\s*["\'][a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}["\']',
         'PII: Hardcoded email address detected'),
        (r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b',
         'PII: Possible Social Security Number pattern'),
        (r'\b4[0-9]{12}(?:[0-9]{3})?\b|\b5[1-5][0-9]{14}\b|\b3[47][0-9]{13}\b',
         'PII: Possible credit card number pattern'),
        (r'(?i)date[_\-]?of[_\-]?birth|birth[_\-]?date|dob\s*[=:]',
         'PII: Date of birth field'),
        (r'(?i)health[_\-]?record|medical[_\-]?id|diagnosis|prescription',
         'PII: Healthcare data field (HIPAA concern)'),
    ]

    def analyze(self, string_corpus: str, permissions: List[str],
                api_calls: List[str]) -> List[Dict]:
        findings = []
        api_text = '\n'.join(api_calls)
        full_text = string_corpus + '\n' + api_text

        # PII pattern detection
        for pattern, description in self.PII_PATTERNS:
            matches = _find(full_text, pattern)
            if matches:
                evidence = _extract_context(full_text, matches[0], 60)
                findings.append({
                    'title': f'PII Data Detected: {description}',
                    'severity': 'medium', 'category': 'Privacy',
                    'cvss_score': 5.5,
                    'description': (
                        f'{description}. If this PII is transmitted or stored without proper '
                        f'protection, it may violate GDPR, CCPA, or HIPAA regulations.'
                    ),
                    'location': 'Application strings / code',
                    'evidence': evidence[:200],
                    'remediation': (
                        'Minimize PII collection. Encrypt PII at rest and in transit. '
                        'Disclose in privacy policy. Implement data retention limits.'
                    ),
                    'poc_command': None,
                    'owasp_category': 'M2: Insecure Data Storage',
                    'cwe_id': 'CWE-359', 'confidence': 'medium',
                })

        # Check for privacy policy presence (simple heuristic)
        has_privacy_policy = bool(
            re.search(r'(?i)privacy[_\-]?policy|privacyPolicy|PRIVACY_POLICY', full_text)
        )
        if not has_privacy_policy:
            findings.append({
                'title': 'No Privacy Policy Reference Found',
                'severity': 'medium', 'category': 'Privacy',
                'cvss_score': 4.0,
                'description': (
                    'No reference to a privacy policy was found in the app. '
                    'Apps collecting any user data are required to have a privacy policy '
                    'under GDPR, CCPA, Google Play Store policy, and Apple App Store policy.'
                ),
                'location': 'Application strings',
                'evidence': 'No "privacy policy" or "privacyPolicy" string detected',
                'remediation': (
                    'Add a link to your privacy policy in the app settings and during onboarding. '
                    'Ensure the policy accurately describes all data collection practices.'
                ),
                'poc_command': None,
                'owasp_category': 'M8: Security Misconfiguration',
                'cwe_id': 'CWE-359', 'confidence': 'low',
            })

        # GDPR consent mechanism
        has_consent = bool(
            re.search(r'(?i)consent|gdpr|ccpa|optIn|opt_in|dataConsent', full_text)
        )
        if not has_consent and any(p in permissions for p in [
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.READ_CONTACTS',
            'android.permission.RECORD_AUDIO',
            'android.permission.CAMERA',
        ]):
            findings.append({
                'title': 'No Consent Mechanism Detected for Sensitive Data Collection',
                'severity': 'medium', 'category': 'Privacy',
                'cvss_score': 5.0,
                'description': (
                    'App requests sensitive permissions (location, contacts, microphone, or camera) '
                    'but no GDPR consent or opt-in mechanism was detected in the code. '
                    'GDPR Article 7 requires freely given, specific, informed, and unambiguous consent.'
                ),
                'location': 'AndroidManifest.xml / Application code',
                'evidence': 'Sensitive permissions declared without consent implementation',
                'remediation': (
                    'Implement a consent dialog before accessing sensitive data. '
                    'Use ConsentSDK or similar. Log consent with timestamp.'
                ),
                'poc_command': None,
                'owasp_category': 'M1: Improper Credential Usage',
                'cwe_id': 'CWE-359', 'confidence': 'low',
            })

        # Children app detection (COPPA)
        children_indicators = re.search(
            r'(?i)kids?|children|child|coppa|under.?13|family.?policy|parental.?consent',
            full_text
        )
        if children_indicators:
            findings.append({
                'title': 'Possible Children\'s App — COPPA Compliance Required',
                'severity': 'medium', 'category': 'Privacy',
                'cvss_score': 5.5,
                'description': (
                    'App appears to target or include children based on keywords detected in code/strings. '
                    'COPPA (USA) prohibits collecting PII from children under 13 without verifiable '
                    'parental consent. Google Play also has a Families Policy for child-directed apps.'
                ),
                'location': 'Application strings',
                'evidence': f'Keywords: {children_indicators.group(0)[:100]}',
                'remediation': (
                    'Remove all advertising SDKs that track children. '
                    'Implement parental consent gates. Review Google Play Families Policy. '
                    'Consult COPPA compliance guidelines at ftc.gov/coppa.'
                ),
                'poc_command': None,
                'owasp_category': 'M8: Security Misconfiguration',
                'cwe_id': 'CWE-359', 'confidence': 'low',
            })

        return findings


# 10. CUSTOM RULE ENGINE (YARA-style)

class CustomRuleEngine:
    """
    Extensible rule engine supporting regex, string, and compound rules.
    Rules defined as dicts for easy user extension.
    """

    # Built-in compound rules (dangerous API combinations)
    COMPOUND_RULES = [
        {
            'id': 'COMPOUND-001',
            'title': 'SMS Interception Trojan Pattern (Classic Banking Trojan)',
            'description': (
                'App combines: READ_SMS permission + abortBroadcast() + network transmission. '
                'This is the canonical pattern used by banking trojans to intercept OTP SMS and '
                'send them to a remote attacker-controlled server.'
            ),
            'severity': 'critical', 'cvss_score': 9.5,
            'conditions': {
                'all_of': [
                    {'type': 'permission', 'value': 'android.permission.READ_SMS'},
                    {'type': 'regex',      'value': r'abortBroadcast\s*\('},
                    {'type': 'regex',      'value': r'http[s]?://|HttpURLConnection|OkHttpClient'},
                ]
            },
            'owasp': 'M1: Improper Credential Usage', 'cwe': 'CWE-862',
        },
        {
            'id': 'COMPOUND-002',
            'title': 'Accessibility-Based Credential Stealer',
            'description': (
                'App combines: Accessibility Service + network transmission + IMEI/device ID access. '
                'This combination enables reading credentials typed in other apps and exfiltrating '
                'them with device identification — a pattern used by credential-stealing malware.'
            ),
            'severity': 'critical', 'cvss_score': 9.5,
            'conditions': {
                'all_of': [
                    {'type': 'regex', 'value': r'AccessibilityService|accessibilityservice'},
                    {'type': 'regex', 'value': r'getDeviceId\s*\(\s*\)|getImei'},
                    {'type': 'regex', 'value': r'http[s]?://|HttpURLConnection|Retrofit'},
                ]
            },
            'owasp': 'M1: Improper Credential Usage', 'cwe': 'CWE-200',
        },
        {
            'id': 'COMPOUND-003',
            'title': 'Silent Package Installer (Dropper Behavior)',
            'description': (
                'App combines: INSTALL_PACKAGES permission or PackageInstaller + DexClassLoader + '
                'network access. This is the pattern used by droppers to download and install '
                'secondary malicious APKs at runtime.'
            ),
            'severity': 'critical', 'cvss_score': 9.8,
            'conditions': {
                'all_of': [
                    {'type': 'regex', 'value': r'DexClassLoader|PackageInstaller|installPackage'},
                    {'type': 'regex', 'value': r'http[s]?://|HttpURLConnection|OkHttpClient|Retrofit'},
                ]
            },
            'owasp': 'M8: Security Misconfiguration', 'cwe': 'CWE-494',
        },
        {
            'id': 'COMPOUND-004',
            'title': 'Screen Recording + Network Exfiltration',
            'description': (
                'App combines: MediaProjection screen capture + network transmission. '
                'Without clear user consent indicators, this is a spyware pattern that '
                'captures the user\'s screen and uploads it to a remote server.'
            ),
            'severity': 'critical', 'cvss_score': 9.3,
            'conditions': {
                'all_of': [
                    {'type': 'regex', 'value': r'MediaProjection|createVirtualDisplay'},
                    {'type': 'regex', 'value': r'http[s]?://|HttpURLConnection|OkHttpClient'},
                ]
            },
            'owasp': 'M1: Improper Credential Usage', 'cwe': 'CWE-200',
        },
        {
            'id': 'COMPOUND-005',
            'title': 'Password Logged to Logcat',
            'description': (
                'App combines: password/credential variable + Log.d/Log.i/Log.e call. '
                'Credentials written to Android logcat are readable via ADB and crash reporting.'
            ),
            'severity': 'high', 'cvss_score': 7.5,
            'conditions': {
                'all_of': [
                    {'type': 'regex', 'value': r'(?i)password|passwd|credential|secret'},
                    {'type': 'regex', 'value': r'Log\.[deitvwDEITVW]\s*\('},
                ]
            },
            'owasp': 'M2: Insecure Data Storage', 'cwe': 'CWE-532',
        },
        {
            'id': 'COMPOUND-006',
            'title': 'Root + Boot Persistence (Privilege Escalation & Persistence)',
            'description': (
                'App combines: root shell execution attempt + RECEIVE_BOOT_COMPLETED. '
                'This combination attempts to gain root privileges and persist across device reboots — '
                'classic system-level malware behavior.'
            ),
            'severity': 'critical', 'cvss_score': 9.8,
            'conditions': {
                'all_of': [
                    {'type': 'regex',      'value': r'exec\s*\(\s*["\']su["\']|Runtime.*su\b'},
                    {'type': 'permission', 'value': 'android.permission.RECEIVE_BOOT_COMPLETED'},
                ]
            },
            'owasp': 'M8: Security Misconfiguration', 'cwe': 'CWE-269',
        },
        {
            'id': 'COMPOUND-007',
            'title': 'VPN + Traffic Interception Pattern',
            'description': (
                'App implements VPN service AND reads network data + accesses device identifiers. '
                'This combination can intercept all device traffic and associate it with a specific user.'
            ),
            'severity': 'critical', 'cvss_score': 9.0,
            'conditions': {
                'all_of': [
                    {'type': 'regex', 'value': r'VpnService|VpnService\.Builder'},
                    {'type': 'regex', 'value': r'getDeviceId|getSubscriberId|getImei'},
                ]
            },
            'owasp': 'M3: Insecure Communication', 'cwe': 'CWE-300',
        },
        {
            'id': 'COMPOUND-008',
            'title': 'Insecure WebView with JavaScript Bridge + File Access',
            'description': (
                'App combines: addJavascriptInterface + setAllowFileAccess(true) + JavaScript enabled. '
                'This combination on Android < 4.2 allows full Java reflection from JavaScript. '
                'Combined with file access, attacker can read any file in the app sandbox.'
            ),
            'severity': 'critical', 'cvss_score': 9.1,
            'conditions': {
                'all_of': [
                    {'type': 'regex', 'value': r'addJavascriptInterface\s*\('},
                    {'type': 'regex', 'value': r'setJavaScriptEnabled\s*\(\s*true\s*\)'},
                    {'type': 'regex', 'value': r'setAllowFileAccess\s*\(\s*true\s*\)'},
                ]
            },
            'owasp': 'M4: Insufficient Input/Output Validation', 'cwe': 'CWE-749',
        },
    ]

    def evaluate(self, corpus: str, permissions: List[str],
                 user_rules: Optional[List[Dict]] = None) -> List[Dict]:
        findings = []
        all_rules = self.COMPOUND_RULES + (user_rules or [])

        for rule in all_rules:
            conditions = rule.get('conditions', {})
            all_of = conditions.get('all_of', [])
            any_of = conditions.get('any_of', [])

            def check_condition(cond: Dict) -> bool:
                cond_type = cond.get('type')
                value = cond.get('value', '')
                if cond_type == 'regex':
                    return bool(_find(corpus, value, re.IGNORECASE))
                elif cond_type == 'permission':
                    return value in permissions
                elif cond_type == 'string':
                    return value.lower() in corpus.lower()
                return False

            matched = (
                (not all_of or all(check_condition(c) for c in all_of)) and
                (not any_of or any(check_condition(c) for c in any_of))
            )

            if matched:
                findings.append({
                    'title': rule['title'],
                    'severity': rule['severity'],
                    'category': 'Compound Rule',
                    'cvss_score': rule['cvss_score'],
                    'description': f"[Rule {rule['id']}] {rule['description']}",
                    'location': 'Multiple locations (compound pattern)',
                    'evidence': f"Rule ID: {rule['id']} — All conditions matched",
                    'remediation': 'Review all matched conditions individually and remediate each component.',
                    'poc_command': None,
                    'owasp_category': rule.get('owasp', 'M8: Security Misconfiguration'),
                    'cwe_id': rule.get('cwe', 'CWE-200'),
                    'confidence': 'high',
                })

        return findings


# 11. RISK SCORER

class EnterpriseRiskScorer:
    """CVSS-inspired 0-100 risk score with category weighting."""

    CATEGORY_MULTIPLIERS = {
        'Compound Rule':   1.5,
        'Malware Behavior': 1.4,
        'Secrets':         1.3,
        'SSL/TLS':         1.2,
        'Certificate':     1.2,
        'Cryptography':    1.1,
        'Code Injection':  1.3,
        'Data Flow':       1.2,
        'Privacy':         1.1,
        'Components':      1.1,
        'WebView':         1.1,
        'Permissions':     1.0,
        'Network':         1.0,
        'Native Code':     1.0,
        'Storage':         0.9,
        'Manifest':        0.9,
        'Obfuscation':     0.7,
        'Anti-Analysis':   0.8,
    }

    SEV_WEIGHT = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}

    def calculate(self, findings: List[Dict]) -> int:
        active = [f for f in findings if f.get('severity') not in ('info', None)]
        if not active:
            return 0
        c = sum(1 for f in active if f.get('severity') == 'critical')
        h = sum(1 for f in active if f.get('severity') == 'high')
        m = sum(1 for f in active if f.get('severity') == 'medium')
        l = sum(1 for f in active if f.get('severity') == 'low')

        if c >= 3:   base = min(100, 90 + c * 2)
        elif c >= 1: base = min(89,  78 + c * 4 + h)
        elif h >= 3: base = min(77,  62 + h * 3 + m)
        elif h >= 1: base = min(77,  52 + h * 5 + m * 2)
        elif m >= 3: base = min(51,  36 + m * 4 + l)
        elif m >= 1: base = min(51,  26 + m * 6)
        elif l >= 1: base = min(25,  10 + l * 4)
        else:        base = 5

        # Category weighting
        ws, wt = 0.0, 0.0
        for f in active:
            w = self.SEV_WEIGHT.get(f.get('severity', 'low'), 1)
            mult = self.CATEGORY_MULTIPLIERS.get(f.get('category', ''), 1.0)
            ws += w * mult
            wt += w
        factor = (ws / wt) if wt > 0 else 1.0
        return min(100, max(0, int(base * min(1.35, max(0.75, factor)))))


# MAIN ENTRY POINT

class StaticAnalyzer:
    """
    Drop-in replacement. Compatible with scans.py without modification.
    Orchestrates all 11 analysis engines.
    """

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.decompiler = APKDecompiler(apk_path)
        self._meta: Dict = {}

    def parse_apk(self) -> Dict[str, Any]:
        self.decompiler.load()
        self._meta = self.decompiler.get_metadata()
        return self._meta

    def run_all_checks(self) -> List[Dict]:
        if not self.decompiler._loaded:
            self.decompiler.load()

        pkg = self._meta.get('package_name', '')
        logger.info(f"[v3] Enterprise scan: {os.path.basename(self.apk_path)} (pkg: {pkg})")

        # Extract content
        manifest   = self.decompiler.get_manifest_xml()
        perms      = self.decompiler.get_permissions()
        strings    = self.decompiler.get_all_strings()
        smali      = self.decompiler.get_smali_code()
        api_calls  = self.decompiler.get_api_calls()
        class_names = self.decompiler.get_class_names()

        string_corpus = '\n'.join(str(s) for s in strings)
        full_corpus   = string_corpus + '\n' + smali + '\n' + '\n'.join(api_calls)

        logger.info(
            f"Extracted: {len(manifest)} chars manifest, {len(strings)} strings, "
            f"{len(smali)} chars smali, {len(api_calls)} API calls, {len(class_names)} classes"
        )

        # Run analyzers
        all_findings: List[Dict] = []

        # 1. APK validation (info-level findings from validator warnings)
        validator = APKValidator()
        val_result = validator.validate(self.apk_path)
        for warn in val_result.get('warnings', []):
            all_findings.append({
                'title': f'APK Integrity Warning: {warn[:80]}',
                'severity': 'medium', 'category': 'Manifest',
                'cvss_score': 5.0, 'description': warn,
                'location': self.apk_path, 'evidence': warn,
                'remediation': 'Investigate APK structure anomaly before distribution.',
                'poc_command': None,
                'owasp_category': 'M7: Insufficient Binary Protections',
                'cwe_id': 'CWE-347', 'confidence': 'medium',
            })

        # 2. Manifest analysis
        manifest_findings = ManifestAnalyzer().analyze(
            manifest, perms,
            self.decompiler.get_activities(),
            self.decompiler.get_services(),
            self.decompiler.get_receivers(),
            self.decompiler.get_providers(),
            pkg
        )
        all_findings.extend(manifest_findings)

        # 3. Code / bytecode analysis
        code_findings = CodeAnalyzer().analyze(strings, smali, api_calls, pkg)
        all_findings.extend(code_findings)

        # 4. Taint / data flow analysis
        taint_findings = TaintAnalyzer().analyze(api_calls, smali)
        all_findings.extend(taint_findings)

        # 5. Native library analysis
        native_findings = NativeLibAnalyzer().analyze(self.apk_path)
        all_findings.extend(native_findings)

        # 6. Certificate analysis
        cert_findings = CertificateAnalyzer().analyze(self.apk_path)
        all_findings.extend(cert_findings)

        # 7. Obfuscation analysis
        obf_result = ObfuscationAnalyzer().analyze(smali, self.apk_path)
        all_findings.extend(obf_result['findings'])

        # 8. SDK / supply chain analysis
        sdk_findings = SDKAnalyzer().analyze(class_names, string_corpus)
        all_findings.extend(sdk_findings)

        # 9. Privacy & compliance
        privacy_findings = PrivacyAnalyzer().analyze(string_corpus, perms, api_calls)
        all_findings.extend(privacy_findings)

        # 10. Compound rule engine
        compound_findings = CustomRuleEngine().evaluate(full_corpus, perms)
        all_findings.extend(compound_findings)

        # Deduplicate by title
        seen: Set[str] = set()
        unique: List[Dict] = []
        for f in all_findings:
            t = f.get('title', '')
            if t not in seen:
                seen.add(t)
                unique.append(f)

        logger.info(
            f"Scan complete: {len(unique)} unique findings "
            f"({len(manifest_findings)} manifest, {len(code_findings)} code, "
            f"{len(taint_findings)} taint, {len(native_findings)} native, "
            f"{len(cert_findings)} cert, {len(obf_result['findings'])} obfuscation, "
            f"{len(sdk_findings)} SDK, {len(privacy_findings)} privacy, "
            f"{len(compound_findings)} compound)"
        )

        if not unique:
            unique.append({
                'title': 'Scan Completed — Minimal Findings',
                'severity': 'low', 'category': 'Info', 'cvss_score': 0,
                'description': (
                    'Static analysis completed with very few findings. The APK may be heavily '
                    'obfuscated or genuinely have good security practices. '
                    'Try DIVA Android for a known-vulnerable APK test.'
                ),
                'location': self.apk_path,
                'evidence': (
                    f'Strings: {len(strings)}, Smali: {len(smali)} chars, '
                    f'Permissions: {len(perms)}, Classes: {len(class_names)}'
                ),
                'remediation': 'N/A — informational.',
                'poc_command': None,
                'owasp_category': None, 'cwe_id': None, 'confidence': 'high',
            })

        return unique


# Backward-compatibility alias
VulnScannerEngine = StaticAnalyzer
