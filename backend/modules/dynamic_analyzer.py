"""Android dynamic analysis engine.

The runner executes APKs only on an explicitly selected Android test target.
It uses ADB for installation, lifecycle control, UI exercise, log collection,
runtime permission inspection, process diagnostics, and (when the app permits
``run-as``) sandbox storage inspection.  Every command is bounded and the app
is force-stopped and uninstalled in ``finally``.

This is intentionally evidence-driven: unavailable capabilities are reported
as coverage gaps rather than converted into findings.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from dotenv import dotenv_values

logger = logging.getLogger(__name__)


def _dynamic_setting(name: str, default: str = "") -> str:
    """Resolve dynamic-lab settings even when the Flask launcher skipped .env.

    Some Windows launchers preserve an empty process variable, which prevents
    python-dotenv's normal application-level load from replacing it. Reading
    the backend file here keeps device selection consistent for every worker.
    """
    process_value = os.getenv(name)
    if process_value and process_value.strip():
        return process_value.strip()

    env_path = Path(__file__).resolve().parents[1] / ".env"
    file_value = dotenv_values(env_path).get(name) if env_path.exists() else None
    if file_value and str(file_value).strip():
        return str(file_value).strip()
    return default


class DynamicAnalysisError(RuntimeError):
    """Raised when the dynamic test environment cannot safely run a scan."""


@dataclass
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass
class DynamicAnalysisResult:
    findings: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class DynamicAnalyzer:
    """Run a bounded Android runtime assessment through ADB.

    Environment variables:
      DYNAMIC_ANALYSIS_DEVICE: adb serial. Required unless exactly one emulator
        is connected.
      ANDROID_ADB_PATH: explicit adb executable path (default: PATH lookup).
      DYNAMIC_ALLOW_PHYSICAL: set ``true`` only for an authorized lab device.
      DYNAMIC_MONKEY_EVENTS: number of safe UI events (default 150, max 1000).
      DYNAMIC_ANALYSIS_TIMEOUT: overall exercise timeout in seconds (default 90).
    """

    SENSITIVE_PATTERNS = [
        ("Authentication token exposed at runtime", "critical", "CWE-532",
         re.compile(r"(?i)(?:bearer\s+[a-z0-9._~+/=-]{12,}|(?:access|auth|refresh)[_-]?token\s*[:=]\s*[^\s,;]{8,})")),
        ("Session credential exposed at runtime", "high", "CWE-532",
         re.compile(r"(?i)(?:session(?:id|token)?|connect\.sid|phpsessid|jsessionid)\s*[:=]\s*[^\s,;]{8,}")),
        ("JWT exposed at runtime", "high", "CWE-532",
         re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
        ("API credential exposed at runtime", "high", "CWE-532",
         re.compile(r"(?i)(?:api[_-]?key|client[_-]?secret)\s*[:=]\s*[A-Za-z0-9._~+/-]{16,}")),
        ("Password exposed at runtime", "high", "CWE-532",
         re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}")),
        ("Private key material exposed at runtime", "critical", "CWE-532",
         re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
        ("Cloud credential exposed at runtime", "critical", "CWE-532",
         re.compile(r"(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36})")),
    ]
    CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
    CARD_CONTEXT_RE = re.compile(
        r"(?i)(?:\b(?:payment|credit|debit)[ _-]*card(?:[ _-]*(?:number|no|num))?"
        r"|\bcard(?:[ _-]*(?:number|no|num))?|\bpan|\bcc(?:[ _-]*(?:number|no|num))?)"
        r"\s*[:=]?\s*$"
    )
    LOGCAT_PREFIX_RE = re.compile(
        r"^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d+\s+\d+\s+[A-Z]\s+[^:]+:\s*"
    )
    CLEARTEXT_URL_RE = re.compile(
        r"(?i)\b(?:http|ws|ftp)://(?!127\.0\.0\.1|localhost|10\.0\.2\.2)([^\s\]\[<>'\"]+)"
    )
    CLEARTEXT_VIOLATION_RE = re.compile(
        r"(?i)(?:CleartextNetworkViolation|StrictMode.*cleartext|cleartext network traffic detected)"
    )
    TLS_BYPASS_RE = re.compile(
        r"(?i)(?:trust(?:ing)? all certificates|hostname verification disabled|unsafe hostname verifier|ssl verification disabled)"
    )
    CRASH_RE = re.compile(r"(?i)(FATAL EXCEPTION|ANR in\s+|Process .* has died|native crash)")

    def __init__(self, apk_path: str, package_name: str,
                 progress_callback: Callable[[int, str], None] | None = None,
                 scan_profile: str = "quick"):
        self.apk_path = str(Path(apk_path).resolve())
        self.package_name = (package_name or "").strip()
        self.progress_callback = progress_callback or (lambda *_: None)
        self.adb = _dynamic_setting("ANDROID_ADB_PATH") or shutil.which("adb")
        self.serial = _dynamic_setting("DYNAMIC_ANALYSIS_DEVICE")
        self.allow_physical = _dynamic_setting("DYNAMIC_ALLOW_PHYSICAL", "false").lower() == "true"
        self.scan_profile = "deep" if scan_profile == "deep" else "quick"
        if self.scan_profile == "deep":
            event_value = _dynamic_setting("DYNAMIC_DEEP_MONKEY_EVENTS", "500")
            timeout_value = _dynamic_setting("DYNAMIC_DEEP_ANALYSIS_TIMEOUT", "180")
        else:
            event_value = _dynamic_setting("DYNAMIC_MONKEY_EVENTS", "150")
            timeout_value = _dynamic_setting("DYNAMIC_ANALYSIS_TIMEOUT", "90")
        self.events = max(1, min(2000, int(event_value)))
        self.exercise_timeout = max(20, min(900, int(timeout_value)))
        self.command_timeout = 30
        self._installed = False
        self._coverage: list[dict] = []
        logger.info("Dynamic target configuration loaded: serial=%s, adb=%s, profile=%s, events=%s",
                    self.serial or "automatic", self.adb or "not found",
                    self.scan_profile, self.events)

    def _progress(self, percent: int, stage: str):
        self.progress_callback(percent, stage)

    def _run(self, *args: str, timeout: int | None = None, check: bool = False) -> CommandResult:
        cmd = [self.adb, "-s", self.serial, *map(str, args)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace",
                                  timeout=timeout or self.command_timeout)
        except subprocess.TimeoutExpired as exc:
            raise DynamicAnalysisError(f"ADB command timed out: {' '.join(args[:3])}") from exc
        result = CommandResult(cmd, proc.returncode, proc.stdout or "", proc.stderr or "")
        if check and result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()[:500]
            raise DynamicAnalysisError(f"ADB command failed ({' '.join(args[:3])}): {detail}")
        return result

    def _shell(self, *args: str, timeout: int | None = None, check: bool = False) -> CommandResult:
        return self._run("shell", *args, timeout=timeout, check=check)

    def _select_device(self):
        if not self.adb:
            raise DynamicAnalysisError(
                "ADB was not found. Install Android SDK Platform Tools or set ANDROID_ADB_PATH."
            )
        proc = subprocess.run([self.adb, "devices", "-l"], capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=15)
        devices = []
        reported_targets = []
        for line in proc.stdout.splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 2:
                reported_targets.append(f"{fields[0]} ({fields[1]})")
                if fields[1] == "device":
                    devices.append(fields[0])
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip()[:500] or "no diagnostic output"
            raise DynamicAnalysisError(f"ADB device discovery failed: {detail}")
        if self.serial:
            if self.serial not in devices:
                observed = ", ".join(reported_targets) or "no Android targets"
                raise DynamicAnalysisError(
                    f"Configured Android target '{self.serial}' is not connected and authorized. "
                    f"ADB reported: {observed}."
                )
        else:
            emulators = [d for d in devices if d.startswith("emulator-")]
            if len(emulators) != 1:
                observed = ", ".join(reported_targets) or "no Android targets"
                raise DynamicAnalysisError(
                    "Set DYNAMIC_ANALYSIS_DEVICE to one dedicated emulator serial. "
                    "Automatic selection is allowed only when exactly one emulator is connected. "
                    f"ADB reported: {observed}."
                )
            self.serial = emulators[0]
        qemu = self._shell("getprop", "ro.kernel.qemu", check=True).stdout.strip()
        if qemu != "1" and not self.allow_physical:
            raise DynamicAnalysisError(
                "Dynamic scans are restricted to emulators by default. Set "
                "DYNAMIC_ALLOW_PHYSICAL=true only for an authorized disposable lab device."
            )

    def _coverage_item(self, name: str, status: str, detail: str):
        self._coverage.append({"name": name, "status": status, "detail": detail})

    @staticmethod
    def _valid_payment_card(candidate: str) -> bool:
        """Accept only plausible 13-19 digit PANs that pass the Luhn check."""
        digits = re.sub(r"[ -]", "", candidate)
        if not 13 <= len(digits) <= 19 or not digits.isdigit() or len(set(digits)) == 1:
            return False
        checksum = 0
        for offset, char in enumerate(reversed(digits)):
            value = int(char)
            if offset % 2 == 1:
                value *= 2
                if value > 9:
                    value -= 9
            checksum += value
        return checksum % 10 == 0

    @classmethod
    def _redact(cls, value: str) -> str:
        value = value.strip().replace("\x00", "")
        value = re.sub(r"(?i)(bearer\s+)[^\s]+", r"\1[REDACTED]", value)
        value = re.sub(r"(?i)((?:password|passwd|pwd|token|secret)[_-]?\w*\s*[:=]\s*)[^\s,;]+", r"\1[REDACTED]", value)
        value = cls.CARD_CANDIDATE_RE.sub(
            lambda match: "[REDACTED-PAYMENT-CARD]"
            if cls._valid_payment_card(match.group(0)) else match.group(0),
            value,
        )
        return value[:700]

    def _finding(self, title: str, severity: str, category: str, description: str,
                 evidence: str, remediation: str, cwe: str, confidence="high") -> dict:
        cvss = {"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1}.get(severity, 0.0)
        owasp_category = {
            "Runtime Storage": "MASVS-STORAGE",
            "Runtime Logging": "MASVS-STORAGE",
            "Runtime Network": "MASVS-NETWORK",
            "Runtime Platform": "MASVS-PLATFORM",
            "Runtime Resilience": "MASVS-RESILIENCE",
            "Runtime Privacy": "MASVS-PRIVACY",
        }.get(category, "MASVS-CODE")
        return {
            "title": title, "severity": severity, "category": category,
            "cvss_score": cvss, "description": description,
            "location": f"Runtime on {self.serial}", "evidence": self._redact(evidence),
            "remediation": remediation, "poc_command": None,
            "confidence": confidence, "cwe_id": cwe,
            "owasp_category": owasp_category,
        }

    def _install_apk(self) -> tuple[CommandResult, bool]:
        """Install the APK and safely retry Android's legacy target-SDK block."""
        install = self._run("install", "-r", "-t", "-g", self.apk_path, timeout=180)
        detail = install.stdout + install.stderr
        used_legacy_bypass = False
        if install.returncode != 0 and "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in detail:
            install = self._run(
                "install", "--bypass-low-target-sdk-block", "-r", "-t", "-g",
                self.apk_path, timeout=180,
            )
            used_legacy_bypass = True
        return install, used_legacy_bypass

    @staticmethod
    def _installed_flags(package_dump: str) -> set[str]:
        flags: set[str] = set()
        for group in re.findall(r"(?:pkgFlags|privateFlags)=\[([^\]]*)\]", package_dump):
            flags.update(re.findall(r"\b[A-Z][A-Z0-9_]+\b", group))
        return flags

    def _inspect_installed_security(self, package_dump: str) -> tuple[list[dict], dict]:
        """Evaluate security-relevant properties of the installed runtime package."""
        findings = []
        flags = self._installed_flags(package_dump)
        checks = {
            "debuggable": "DEBUGGABLE" in flags,
            "test_only": "TEST_ONLY" in flags,
            "backup_enabled": "ALLOW_BACKUP" in flags,
            "cleartext_permitted": "USES_CLEARTEXT_TRAFFIC" in flags,
            "profileable_by_shell": "PROFILEABLE_BY_SHELL" in flags,
        }

        if checks["debuggable"]:
            findings.append(self._finding(
                "Application is debuggable at runtime", "medium", "Runtime Resilience",
                "The installed application exposes Android debugging capabilities that should be disabled in a production build.",
                "Installed package flag: DEBUGGABLE",
                "Ship a release build with android:debuggable=false and remove development-only diagnostic features.",
                "CWE-489",
            ))
        if checks["test_only"]:
            findings.append(self._finding(
                "Test-only application build installed", "medium", "Runtime Resilience",
                "The installed APK is marked TEST_ONLY, indicating that development or test behavior may be present.",
                "Installed package flag: TEST_ONLY",
                "Distribute a signed production build without android:testOnly and remove test endpoints or credentials.",
                "CWE-489", "medium",
            ))
        if checks["backup_enabled"]:
            findings.append(self._finding(
                "Application data backup is enabled", "low", "Runtime Storage",
                "The installed package permits Android backup. Sensitive files can be exposed if backup exclusion rules are incomplete.",
                "Installed package flag: ALLOW_BACKUP",
                "Disable backup when it is not required, or define data-extraction and backup rules that exclude credentials and sensitive records.",
                "CWE-530", "medium",
            ))
        if checks["cleartext_permitted"]:
            findings.append(self._finding(
                "Installed application permits cleartext traffic", "medium", "Runtime Network",
                "Android reports that the installed application permits cleartext network communication. This is a configuration risk; observed traffic is reported separately.",
                "Installed package flag: USES_CLEARTEXT_TRAFFIC",
                "Disable cleartext traffic with Network Security Configuration and migrate every endpoint to TLS.",
                "CWE-319", "medium",
            ))
        if checks["profileable_by_shell"]:
            findings.append(self._finding(
                "Application is profileable by the shell user", "low", "Runtime Resilience",
                "The production process can be profiled through ADB, increasing runtime information available to a local attacker.",
                "Installed private flag: PROFILEABLE_BY_SHELL",
                "Disable profileable-by-shell in production unless it is an explicit operational requirement.",
                "CWE-489", "medium",
            ))

        self._coverage_item(
            "Installed package security flags", "completed",
            f"Evaluated DEBUGGABLE, TEST_ONLY, ALLOW_BACKUP, cleartext, and profiling flags; {sum(checks.values())} risk flag(s) enabled.",
        )
        return findings, {"flags": sorted(flags), "checks": checks}

    def _jdwp_snapshot(self) -> set[str]:
        """Take a bounded snapshot from adb's otherwise streaming JDWP service."""
        cmd = [self.adb, "-s", self.serial, "jdwp"]
        output = ""
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=3,
            )
            output = proc.stdout or ""
        except subprocess.TimeoutExpired as exc:
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
        return {line.strip() for line in output.splitlines() if line.strip().isdigit()}

    def _inspect_runtime_debug_surfaces(self, pid: str) -> tuple[list[dict], dict]:
        findings = []
        errors = []
        jdwp_exposed = False
        webview_sockets = []

        try:
            jdwp_exposed = pid in self._jdwp_snapshot()
        except (OSError, subprocess.SubprocessError) as exc:
            errors.append(str(exc))

        try:
            unix_sockets = self._shell("cat", "/proc/net/unix", timeout=20)
            for line in unix_sockets.stdout.splitlines():
                lowered = line.lower()
                if ("devtools_remote" in lowered and
                        (pid in line or self.package_name.lower() in lowered)):
                    webview_sockets.append(line.strip()[-240:])
        except DynamicAnalysisError as exc:
            errors.append(str(exc))

        if jdwp_exposed:
            findings.append(self._finding(
                "JDWP debugging exposed at runtime", "medium", "Runtime Resilience",
                "The running process is advertised through Android's Java Debug Wire Protocol and can be inspected through an authorized ADB connection.",
                f"adb jdwp listed process {pid}",
                "Disable android:debuggable and verify that production processes are absent from adb jdwp output.",
                "CWE-489",
            ))
        if webview_sockets:
            findings.append(self._finding(
                "WebView debugging exposed at runtime", "high", "Runtime Resilience",
                "The app created a WebView DevTools socket. An attacker with device debugging access can inspect or modify WebView content and traffic.",
                webview_sockets[0],
                "Call WebView.setWebContentsDebuggingEnabled(false) in production and never enable it independently of a debug-build check.",
                "CWE-489",
            ))

        self._coverage_item(
            "Runtime debugging surfaces", "partial" if errors else "completed",
            f"Checked JDWP and WebView DevTools exposure; found {int(jdwp_exposed) + len(webview_sockets)} exposed surface(s)."
            + (f" {len(errors)} check(s) unavailable." if errors else ""),
        )
        return findings, {
            "jdwp_exposed": jdwp_exposed,
            "webview_devtools_sockets": len(webview_sockets),
            "errors": errors,
        }

    def _collect_sensitive_app_ops(self) -> dict:
        """Record privacy-sensitive operations used during this bounded run."""
        sensitive_ops = {
            "CAMERA", "RECORD_AUDIO", "FINE_LOCATION", "COARSE_LOCATION",
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG",
            "READ_SMS", "SEND_SMS", "READ_PHONE_STATE", "BODY_SENSORS",
            "READ_CLIPBOARD", "WRITE_CLIPBOARD",
        }
        try:
            result = self._shell("cmd", "appops", "get", self.package_name, timeout=25)
        except DynamicAnalysisError as exc:
            self._coverage_item("Runtime privacy operations", "unavailable", str(exc))
            return {"status": "unavailable", "reason": str(exc), "observed": []}
        if result.returncode != 0:
            reason = self._redact(result.stderr or result.stdout) or "appops query was denied"
            self._coverage_item("Runtime privacy operations", "unavailable", reason)
            return {"status": "unavailable", "reason": reason, "observed": []}

        observed = []
        for line in result.stdout.splitlines():
            match = re.match(r"\s*([A-Z_]+):\s*(.*)", line)
            if not match or match.group(1) not in sensitive_ops:
                continue
            detail = match.group(2)
            if re.search(r"(?:time=|duration=|running=true|foreground)", detail, re.I):
                observed.append({"operation": match.group(1), "detail": self._redact(detail)})
        self._coverage_item(
            "Runtime privacy operations", "completed",
            f"Queried Android AppOps and observed {len(observed)} privacy-sensitive operation(s) during the scan.",
        )
        return {"status": "completed", "observed": observed}

    def _scan_text_evidence(self, text: str, source: str) -> list[dict]:
        findings, seen = [], set()
        for line in text.splitlines():
            # Threadtime logcat prefixes contain timestamps, PIDs and UIDs. Scan
            # only the actual message so unrelated system identifiers cannot be
            # concatenated into a payment-card candidate.
            payload = self.LOGCAT_PREFIX_RE.sub("", line, count=1) if source == "logcat" else line
            for title, severity, cwe, pattern in self.SENSITIVE_PATTERNS:
                if pattern.search(payload) and title not in seen:
                    findings.append(self._finding(
                        title, severity, "Runtime Logging" if source == "logcat" else "Runtime Storage",
                        f"Sensitive material was observable in {source} while the app was running.",
                        line, "Remove sensitive values from logs and plaintext storage. Store credentials in "
                              "Android Keystore-backed protection and redact diagnostic output.", cwe,
                    ))
                    seen.add(title)
            for candidate in self.CARD_CANDIDATE_RE.finditer(payload):
                context = payload[max(0, candidate.start() - 64):candidate.start()]
                if (self.CARD_CONTEXT_RE.search(context) and
                        self._valid_payment_card(candidate.group(0)) and
                        "Payment card data exposed at runtime" not in seen):
                    findings.append(self._finding(
                        "Payment card data exposed at runtime", "high",
                        "Runtime Logging" if source == "logcat" else "Runtime Storage",
                        f"A Luhn-valid payment card number was observable in {source} while the app was running.",
                        line,
                        "Never log or store full payment card numbers. Tokenize payment data and retain only a masked value when required.",
                        "CWE-532" if source == "logcat" else "CWE-312",
                    ))
                    seen.add("Payment card data exposed at runtime")
                    break
            match = self.CLEARTEXT_URL_RE.search(payload)
            if match and "Cleartext traffic observed" not in seen:
                findings.append(self._finding(
                    "Cleartext traffic observed", "high", "Runtime Network",
                    "The running application exposed a non-local cleartext URL, allowing traffic interception or modification.",
                    match.group(0), "Use HTTPS for all remote endpoints, disable cleartext traffic, and validate TLS correctly.",
                    "CWE-319", "medium",
                ))
                seen.add("Cleartext traffic observed")
            if (self.CLEARTEXT_VIOLATION_RE.search(payload) and
                    "Android detected cleartext network use" not in seen):
                findings.append(self._finding(
                    "Android detected cleartext network use", "high", "Runtime Network",
                    "Android StrictMode or the network stack reported cleartext communication while the application was running.",
                    line,
                    "Use TLS for every remote connection and set cleartextTrafficPermitted=false in Network Security Configuration.",
                    "CWE-319",
                ))
                seen.add("Android detected cleartext network use")
            if (self.TLS_BYPASS_RE.search(payload) and
                    "TLS validation bypass indicated at runtime" not in seen):
                findings.append(self._finding(
                    "TLS validation bypass indicated at runtime", "high", "Runtime Network",
                    "Runtime output indicates that certificate or hostname validation may have been disabled.",
                    line,
                    "Use the platform trust manager and default hostname verifier; remove trust-all certificates and verification bypasses.",
                    "CWE-295", "medium",
                ))
                seen.add("TLS validation bypass indicated at runtime")
        return findings

    def _inspect_storage(self) -> tuple[list[dict], dict]:
        findings = []
        external_root = f"/sdcard/Android/data/{self.package_name}"
        external_errors = []
        try:
            external_listing = self._shell(
                "find", external_root, "-type", "f", timeout=20
            ).stdout
            external_files = [
                line.strip() for line in external_listing.splitlines()
                if line.strip() and re.fullmatch(r"[A-Za-z0-9_./-]+", line.strip())
            ][:200]
        except DynamicAnalysisError as exc:
            external_files = []
            external_errors.append(str(exc))
        external_content = []
        for name in external_files[:30]:
            try:
                content = self._shell("head", "-c", "65536", name, timeout=10)
                if content.returncode == 0 and content.stdout:
                    external_content.append(content.stdout)
            except DynamicAnalysisError as exc:
                external_errors.append(str(exc))
        findings.extend(self._scan_text_evidence(
            "\n".join(external_content), "external application storage"
        ))
        self._coverage_item(
            "External application storage",
            "partial" if external_errors else "completed",
            f"Inspected {len(external_content)} of {len(external_files)} runtime-created files."
            + (f" {len(external_errors)} operation(s) timed out or were unavailable."
               if external_errors else ""),
        )

        try:
            probe = self._shell("run-as", self.package_name, "pwd", timeout=15)
        except DynamicAnalysisError as exc:
            self._coverage_item("Application sandbox storage", "unavailable", str(exc))
            return findings, {
                "accessible": False, "reason": str(exc),
                "external_files_discovered": len(external_files),
            }
        if probe.returncode != 0:
            self._coverage_item("Application sandbox storage", "unavailable",
                                "run-as denied access; use a rooted disposable emulator for deeper storage inspection.")
            return findings, {
                "accessible": False, "reason": (probe.stderr or probe.stdout).strip()[:300],
                "external_files_discovered": len(external_files),
            }
        sandbox_errors = []
        try:
            listing = self._shell(
                "run-as", self.package_name, "find", ".", "-maxdepth", "5",
                "-type", "f", "-print", timeout=20,
            ).stdout
        except DynamicAnalysisError as exc:
            listing = ""
            sandbox_errors.append(str(exc))
        candidates = []
        for name in listing.splitlines()[:200]:
            if (re.fullmatch(r"[A-Za-z0-9_./-]+", name.strip()) and
                    re.search(r"(?i)(shared_prefs|databases|files|app_webview).*(xml|json|db|sqlite|txt|log)?$", name)):
                candidates.append(name.strip())
        combined = []
        inspected = []
        exposed_modes = []
        for name in candidates[:30]:
            try:
                result = self._shell(
                    "run-as", self.package_name, "head", "-c", "65536", name,
                    timeout=10,
                )
                if result.returncode == 0 and result.stdout:
                    combined.append(result.stdout)
                    inspected.append(name)
                mode_result = self._shell(
                    "run-as", self.package_name, "stat", "-c", "%a", name,
                    timeout=10,
                )
                mode_match = re.search(r"\b([0-7]{3,4})\b", mode_result.stdout)
                if mode_match:
                    mode = mode_match.group(1)[-3:]
                    other_permissions = int(mode[-1])
                    if other_permissions & 6:
                        exposed_modes.append({"file": name, "mode": mode})
            except DynamicAnalysisError as exc:
                sandbox_errors.append(str(exc))
        self._coverage_item(
            "Application sandbox storage",
            "partial" if sandbox_errors else "completed",
            f"Inspected {len(inspected)} readable runtime-created files."
            + (f" {len(sandbox_errors)} operation(s) timed out or were unavailable."
               if sandbox_errors else ""),
        )
        findings.extend(self._scan_text_evidence("\n".join(combined), "application sandbox storage"))
        if exposed_modes:
            evidence = ", ".join(
                f"{item['file']} (mode {item['mode']})" for item in exposed_modes[:8]
            )
            findings.append(self._finding(
                "App sandbox files are world-readable or writable", "high", "Runtime Storage",
                "Runtime-created private files grant read or write access to other Linux users, allowing another process to disclose or modify application data.",
                evidence,
                "Create private files with mode 0600 and private directories with mode 0700. Share data only through a permission-protected content provider.",
                "CWE-732",
            ))
        return findings, {
            "accessible": True, "files_discovered": len(candidates), "files_inspected": inspected,
            "world_exposed_files": exposed_modes,
            "external_files_discovered": len(external_files),
        }

    def run(self) -> DynamicAnalysisResult:
        if not os.path.isfile(self.apk_path):
            raise DynamicAnalysisError("APK file no longer exists.")
        if not self.package_name or not re.fullmatch(r"[A-Za-z0-9_.]+", self.package_name):
            raise DynamicAnalysisError("A valid Android package name could not be determined from the APK.")

        started = time.time()
        findings: list[dict] = []
        metadata = {
            "engine": "VulnScanner Android Runtime Engine 2.0",
            "package_name": self.package_name,
            "apk_sha256": hashlib.sha256(Path(self.apk_path).read_bytes()).hexdigest(),
            "authorized_target_required": True,
            "scan_profile": self.scan_profile,
            "standards": ["OWASP MASVS", "OWASP MASTG"],
            "detector_catalog": [
                "installed package debug, test, backup, cleartext, and profiling flags",
                "JDWP and WebView DevTools runtime exposure",
                "credentials, private keys, cloud keys, JWTs, sessions, and payment data in logs or storage",
                "cleartext URLs, Android cleartext violations, and TLS validation bypass indicators",
                "runtime crashes and application-not-responding events",
                "sensitive external and sandbox storage plus unsafe file permissions",
                "privacy-sensitive Android AppOps exercised during the scan",
            ],
        }
        try:
            self._progress(5, "Validating Android test target")
            self._select_device()
            metadata["device_serial"] = self.serial
            metadata["device"] = {
                "model": self._shell("getprop", "ro.product.model").stdout.strip(),
                "android_version": self._shell("getprop", "ro.build.version.release").stdout.strip(),
                "api_level": self._shell("getprop", "ro.build.version.sdk").stdout.strip(),
                "emulator": self._shell("getprop", "ro.kernel.qemu").stdout.strip() == "1",
            }
            self._coverage_item("Dedicated target validation", "completed", "ADB target is connected and authorized.")

            self._progress(15, "Installing APK")
            install, used_legacy_bypass = self._install_apk()
            if install.returncode != 0 or "Success" not in install.stdout:
                raise DynamicAnalysisError(f"APK installation failed: {(install.stderr or install.stdout).strip()[:500]}")
            self._installed = True
            metadata["legacy_target_sdk_bypass"] = used_legacy_bypass
            self._coverage_item(
                "APK installation", "completed",
                "Installed with runtime permissions granted for test coverage."
                + (" Android's low target-SDK test-lab bypass was required." if used_legacy_bypass else ""),
            )

            self._shell("am", "force-stop", self.package_name)
            self._run("logcat", "-c")
            package_dump = self._shell("dumpsys", "package", self.package_name).stdout
            metadata["granted_runtime_permissions"] = sorted(set(re.findall(
                r"(android\.permission\.[A-Z0-9_]+): granted=true", package_dump
            )))
            self._coverage_item("Runtime permissions", "completed",
                                f"Observed {len(metadata['granted_runtime_permissions'])} granted permissions.")
            configuration_findings, configuration_meta = self._inspect_installed_security(package_dump)
            findings.extend(configuration_findings)
            metadata["installed_security"] = configuration_meta

            self._progress(30, "Launching application")
            # Resolve the installed launch component first, then start that exact
            # component. Package-only intents are not resolved consistently by
            # recent Android emulator images, while `monkey ... 1` can hang after
            # dispatching its event.
            resolved = self._shell(
                "cmd", "package", "resolve-activity", "--brief",
                "-a", "android.intent.action.MAIN",
                "-c", "android.intent.category.LAUNCHER",
                self.package_name,
                timeout=20,
            )
            components = re.findall(
                r"(?m)^\s*([A-Za-z0-9_.]+/[A-Za-z0-9_.$]+)\s*$",
                resolved.stdout,
            )
            component = next(
                (item for item in reversed(components)
                 if item.startswith(f"{self.package_name}/")),
                None,
            )
            if not component:
                detail = self._redact(resolved.stdout + resolved.stderr)
                raise DynamicAnalysisError(
                    "The APK installed but Android could not resolve its launcher activity"
                    + (f": {detail}" if detail else ".")
                )

            self._shell("input", "keyevent", "KEYCODE_WAKEUP", timeout=10)
            self._shell("wm", "dismiss-keyguard", timeout=10)
            launch_errors = []
            pid = []
            for attempt in range(2):
                try:
                    launch = self._shell("am", "start", "-n", component, timeout=30)
                    launch_output = launch.stdout + launch.stderr
                    if (launch.returncode != 0 or
                            re.search(r"(?i)(error:|unable to resolve|no activity)", launch_output)):
                        detail = self._redact(launch_output) or "Android could not resolve a launcher activity."
                        raise DynamicAnalysisError(
                            f"The APK installed but no launchable activity could be started: {detail}"
                        )
                except DynamicAnalysisError as exc:
                    # Activity Manager can time out after dispatching the intent
                    # on a busy emulator. PID presence is authoritative.
                    launch_errors.append(str(exc))
                for _ in range(8):
                    time.sleep(1)
                    pid = self._shell("pidof", self.package_name).stdout.strip().split()[0:1]
                    if pid:
                        break
                if pid:
                    break
                if attempt == 0:
                    time.sleep(2)
            if not pid:
                raise DynamicAnalysisError(
                    ((launch_errors[-1] + ". ") if launch_errors else "")
                    + f"Launcher activity {component} did not produce a running application process."
                )
            metadata["launch_component"] = component
            metadata["initial_pid"] = pid[0] if pid else None
            self._coverage_item(
                "Application launch", "partial" if launch_errors else "completed",
                "Launcher activity started and the application process was verified."
                + (f" Activity Manager required retry or timed out {len(launch_errors)} time(s)."
                   if launch_errors else ""),
            )

            self._progress(45, "Exercising UI and application lifecycle")
            exercise_error = None
            try:
                monkey = self._shell("monkey", "-p", self.package_name,
                                     "--pct-syskeys", "0", "--pct-appswitch", "0",
                                     "--throttle", "100", "-s", "1337", str(self.events),
                                     timeout=self.exercise_timeout)
            except DynamicAnalysisError as exc:
                # UI automation is one evidence source, not a reason to discard
                # installation, launch, logs, storage, and process diagnostics.
                exercise_error = str(exc)
                monkey = CommandResult([], 124, "", exercise_error)
            metadata["ui_exercise"] = {
                "events_requested": self.events,
                "completed": monkey.returncode == 0,
                "summary": self._redact((monkey.stdout + monkey.stderr)[-1000:]),
            }
            self._coverage_item("Automated UI exercise", "completed" if monkey.returncode == 0 else "partial",
                                (f"Requested {self.events} deterministic non-system UI events."
                                 if not exercise_error else exercise_error))

            debug_findings, debug_meta = self._inspect_runtime_debug_surfaces(pid[0])
            findings.extend(debug_findings)
            metadata["runtime_debug_surfaces"] = debug_meta
            metadata["privacy_app_ops"] = self._collect_sensitive_app_ops()

            self._progress(65, "Collecting runtime evidence")
            current_pid = self._shell("pidof", self.package_name).stdout.strip().split()[0:1]
            if current_pid:
                captured = self._run("logcat", "-d", "-v", "threadtime", "--pid", current_pid[0], timeout=45)
            else:
                captured = self._run("logcat", "-d", "-v", "threadtime", "*:V", timeout=45)
            logcat = captured.stdout
            package_lines = logcat if current_pid else "\n".join(
                line for line in logcat.splitlines()
                if self.package_name.lower() in line.lower() or
                any(x in line for x in ("FATAL EXCEPTION", "AndroidRuntime", "StrictMode"))
            )
            log_findings = self._scan_text_evidence(package_lines, "logcat")
            findings.extend(log_findings)
            crashes = [line for line in package_lines.splitlines() if self.CRASH_RE.search(line)]
            if crashes:
                findings.append(self._finding(
                    "Runtime crash or ANR observed", "medium", "Runtime Stability",
                    "The application crashed or became unresponsive during deterministic UI exercise. "
                    "Crashes can expose diagnostic data or create denial-of-service conditions.",
                    crashes[0], "Review the captured stack trace, handle untrusted input safely, and add regression tests.",
                    "CWE-248", "medium",
                ))
            self._coverage_item(
                "Runtime logs and sensitive-data indicators", "completed",
                f"Collected {len(package_lines.splitlines())} package-relevant log lines and produced {len(log_findings)} evidence-backed finding(s).",
            )
            network_findings = sum(
                1 for item in log_findings if item.get("category") == "Runtime Network"
            )
            self._coverage_item(
                "Cleartext and TLS runtime indicators", "completed",
                f"Inspected captured runtime output for cleartext URLs, StrictMode cleartext violations, and TLS-validation bypass indicators; found {network_findings}.",
            )
            self._coverage_item(
                "Runtime crash and ANR signals", "completed",
                f"Observed {len(crashes)} crash or application-not-responding signal(s).",
            )

            storage_findings, storage_meta = self._inspect_storage()
            findings.extend(storage_findings)
            metadata["storage"] = storage_meta

            self._progress(82, "Collecting process diagnostics")
            metadata["process"] = {
                "pid": self._shell("pidof", self.package_name).stdout.strip(),
                "memory_summary": self._shell("dumpsys", "meminfo", self.package_name).stdout[-4000:],
            }
            self._coverage_item("Process diagnostics", "completed", "Collected PID and memory diagnostics.")

            # Deduplicate identical detector outcomes while retaining first evidence.
            unique = {}
            for item in findings:
                unique.setdefault((item["title"], item["evidence"]), item)
            findings = list(unique.values())
            self._progress(95, "Finalizing dynamic evidence")
        finally:
            if self.adb and self.serial and self._installed:
                try:
                    self._shell("am", "force-stop", self.package_name)
                    uninstall = self._run("uninstall", self.package_name, timeout=60)
                    self._coverage_item("Target cleanup",
                                        "completed" if uninstall.returncode == 0 else "failed",
                                        "Test package removed from the Android target." if uninstall.returncode == 0
                                        else "Automatic uninstall failed; remove the package manually.")
                except Exception as cleanup_error:
                    logger.warning("Dynamic cleanup failed for %s: %s", self.package_name, cleanup_error)
                    self._coverage_item("Target cleanup", "failed", str(cleanup_error)[:300])

        metadata["coverage"] = self._coverage
        metadata["duration_seconds"] = round(time.time() - started, 2)
        metadata["limitations"] = [
            "Automated UI exercise cannot cover authenticated or business-specific workflows without supplied test automation.",
            "Full packet capture, certificate-pinning validation, and method-level instrumentation require an explicitly configured proxy/Frida extension.",
            "Clipboard attribution and sensitive-screen screenshot protection require a supplied test workflow to avoid inspecting unrelated device or user data.",
            "Private sandbox evidence is unavailable for non-debuggable release apps unless the dedicated emulator is rooted.",
            "Emulators do not reproduce all hardware-backed security behavior of physical devices.",
        ]
        return DynamicAnalysisResult(findings=findings, metadata=metadata)
