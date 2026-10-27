"""PMD CLI client: download-on-demand into tools/pmd/ (git-ignored), run as a
subprocess, parse XML output. Never bundled into requirements; if the download
or the JVM is unavailable the caller records 'pmd: unavailable' and the custom
javalang detectors carry the Java analysis (documented limitation, not silent).

Accepted plan policy: 'PMD downloaded on demand... If download fails, Java
quality detection falls back and the report labels PMD unavailable honestly.'
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import urllib.request
import zipfile

PMD_VERSION = os.environ.get("PMD_VERSION", "7.9.0")
PMD_URL = (
    f"https://github.com/pmd/pmd/releases/download/"
    f"pmd_releases%2F{PMD_VERSION}/pmd-dist-{PMD_VERSION}-bin.zip"
)
TOOLS_DIR = os.path.join(os.getcwd(), "tools", "pmd")
RUN_TIMEOUT = int(os.environ.get("PMD_TIMEOUT", "180"))
DOWNLOAD_TIMEOUT = int(os.environ.get("PMD_DOWNLOAD_TIMEOUT", "600"))

RULESET_PATH = os.path.join(os.path.dirname(__file__), "pmd_ruleset.xml")


def ensure_pmd(log=lambda s: None) -> str | None:
    """Return the pmd launcher path, downloading once if permitted. None on failure."""
    candidate = _find_launcher()
    if candidate:
        return candidate
    if os.environ.get("PMD_DISABLE_DOWNLOAD") == "1":
        return None
    try:
        os.makedirs(TOOLS_DIR, exist_ok=True)
        zip_path = os.path.join(TOOLS_DIR, f"pmd-{PMD_VERSION}.zip")
        if not os.path.exists(zip_path):
            log(f"downloading PMD {PMD_VERSION} ({PMD_URL}) ...")
            with urllib.request.urlopen(PMD_URL, timeout=DOWNLOAD_TIMEOUT) as resp, open(zip_path, "wb") as out:
                out.write(resp.read())
        log("extracting PMD ...")
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(TOOLS_DIR)
        return _find_launcher()
    except Exception as e:  # network/JVM failure must not break the pipeline
        log(f"pmd download unavailable: {e}")
        return None


def _find_launcher() -> str | None:
    if not os.path.isdir(TOOLS_DIR):
        return None
    for root, _dirs, files in os.walk(TOOLS_DIR):
        for name in ("pmd.bat", "pmd.cmd", "pmd"):
            if name in files:
                return os.path.join(root, name)
    return None


def run_pmd(target_path: str, log=lambda s: None):
    """Returns ([violation dicts], status): status in {'ok','unavailable','error'}."""
    launcher = ensure_pmd(log)
    if not launcher:
        return [], "unavailable"
    if not os.path.exists(RULESET_PATH):
        return [], "error"
    try:
        # PMD 7 writes progress warnings to the same stream as the report, so
        # write the report to a temp file (-r) instead of parsing stdout.
        with tempfile.TemporaryDirectory(prefix="m2_pmd_") as out_dir:
            report_path = os.path.join(out_dir, "report.xml")
            cmd = [launcher, "check", "-d", os.path.dirname(target_path),
                   "-R", RULESET_PATH, "-f", "xml", "-r", report_path]
            subprocess.run(
                cmd, capture_output=True, text=True, timeout=RUN_TIMEOUT,
                shell=launcher.endswith((".bat", ".cmd")),
                encoding="utf-8", errors="replace")
            if not os.path.exists(report_path):
                return [], "error"
            with open(report_path, "r", encoding="utf-8") as fh:
                xml_text = fh.read()
        violations, errors = _parse_xml(xml_text)
        if errors:
            # PMD itself could not parse the file. Reporting "ok" here would let
            # a failed scan look like a clean one, so the errors are surfaced.
            log(f"pmd reported {len(errors)} processing error(s): {errors[0][:160]}")
            return violations, "error"
        return violations, "ok"
    except Exception as e:
        log(f"pmd run failed: {e}")
        return [], "error"


def _parse_xml(xml_text: str) -> tuple[list[dict], list[str]]:
    """Return (violations, processing_errors) from a PMD XML report.

    PMD reports an unparseable file as an <error> element with msg=..., not as
    a violation. Those errors must be propagated: they mean "nothing analysed".
    """
    import xml.etree.ElementTree as ET
    violations: list[dict] = []
    errors: list[str] = []
    # strip anything before the XML declaration (belt and braces: report file
    # is clean, but keep parsing resilient if stdout is ever reused)
    start = xml_text.find("<?xml")
    if start > 0:
        xml_text = xml_text[start:]
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return violations, [f"unreadable PMD report: {e}"]
    for node in root.iter():
        # PMD 7 reports are namespaced: match the local name only
        local = node.tag.rsplit("}", 1)[-1]
        if local == "violation":
            violations.append({
                "rule": node.get("rule", ""),
                "beginline": int(node.get("beginline", "1") or 1),
                "endline": int(node.get("endline", node.get("beginline", "1")) or 1),
                "description": "".join(node.itertext()).strip(),
                "violation_text": "",
            })
        elif local == "error":
            msg = (node.get("msg") or "".join(node.itertext()).strip()).strip()
            filename = os.path.basename(node.get("filename") or "")
            errors.append(f"{filename}: {msg}" if filename else msg)
    return violations, errors


def run_java_quality(java_path: str, log=lambda s: None) -> tuple[list[dict], str]:
    """CLI-level sampling entry used by agents when analysing uploaded files."""
    return run_pmd(java_path, log)
