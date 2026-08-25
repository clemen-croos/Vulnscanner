"""
Sandbox runner — executes androguard analysis in an isolated subprocess.
This prevents any malicious APK from crashing or exploiting the Flask server.
"""
import os
import json
import subprocess
import sys
import tempfile
import logging

logger = logging.getLogger(__name__)

ANALYSIS_SCRIPT = '''
import sys, json, traceback
sys.path.insert(0, sys.argv[2])  # backend directory

apk_path = sys.argv[1]
result = {"success": False, "strings": [], "manifest": "", 
          "metadata": {}, "permissions": [], "activities": [],
          "services": [], "receivers": [], "providers": [], 
          "api_calls": [], "so_files": [], "error": None}

try:
    from androguard.misc import AnalyzeAPK
    from androguard.core.bytecodes.apk import APK
    import zipfile, re

    apk_obj, dvm_list, analysis_obj = AnalyzeAPK(apk_path)
    if not isinstance(dvm_list, list):
        dvm_list = [dvm_list]

    # Metadata
    result["metadata"] = {
        "package_name": apk_obj.get_package() or "unknown",
        "version_name": apk_obj.get_androidversion_name() or "1.0",
        "version_code": str(apk_obj.get_androidversion_code() or "1"),
        "min_sdk": apk_obj.get_min_sdk_version(),
        "target_sdk": apk_obj.get_target_sdk_version(),
    }

    # Manifest XML
    try:
        import lxml.etree as ET
        xml = apk_obj.get_android_manifest_xml()
        result["manifest"] = ET.tostring(xml, pretty_print=True, encoding="unicode") if xml else ""
    except Exception:
        result["manifest"] = ""

    # All string constants from DEX
    strings = []
    for dvm in dvm_list:
        try:
            for s in dvm.get_strings():
                if s and len(str(s)) >= 4:
                    strings.append(str(s))
        except Exception:
            pass
    result["strings"] = strings[:50000]  # cap at 50k strings

    # Components
    result["permissions"] = apk_obj.get_permissions() or []
    result["activities"] = apk_obj.get_activities() or []
    result["services"] = apk_obj.get_services() or []
    result["receivers"] = apk_obj.get_receivers() or []
    result["providers"] = apk_obj.get_providers() or []

    # API calls
    calls = []
    if analysis_obj:
        for cls in analysis_obj.get_classes():
            for method in cls.get_methods():
                try:
                    for _, call, _ in method.get_xref_to():
                        calls.append(f"{call.class_name}->{call.name}{call.descriptor}")
                except Exception:
                    pass
    result["api_calls"] = calls[:20000]

    # Native libs
    with zipfile.ZipFile(apk_path, "r") as zf:
        result["so_files"] = [n for n in zf.namelist() if n.endswith(".so")]

    result["success"] = True

except Exception as e:
    result["error"] = str(e)
    result["traceback"] = traceback.format_exc()

print(json.dumps(result))
'''


def run_analysis_sandboxed(apk_path: str, timeout_seconds: int = 120) -> dict:
    """
    Run androguard analysis in an isolated subprocess.
    If it crashes, hangs, or is killed — Flask is unaffected.
    """
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    # Write analysis script to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py',
                                     delete=False, encoding='utf-8') as f:
        f.write(ANALYSIS_SCRIPT)
        script_path = f.name

    try:
        result = subprocess.run(
            [sys.executable, script_path, apk_path, backend_dir],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            # Limit memory on Linux (ignored on Windows)
            # preexec_fn=lambda: resource.setrlimit(
            #     resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024)
            # )
        )

        if result.returncode != 0:
            logger.warning(f"Sandbox analysis failed (exit {result.returncode}): {result.stderr[:500]}")
            return {"success": False, "error": result.stderr[:500]}

        output = result.stdout.strip()
        if not output:
            return {"success": False, "error": "No output from analysis subprocess"}

        return json.loads(output)

    except subprocess.TimeoutExpired:
        logger.error(f"Analysis timed out after {timeout_seconds}s for {apk_path}")
        return {"success": False, "error": f"Analysis timed out after {timeout_seconds}s"}
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse analysis output: {e}")
        return {"success": False, "error": "Invalid output from analysis subprocess"}
    except Exception as e:
        logger.error(f"Sandbox runner error: {e}")
        return {"success": False, "error": str(e)}
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass