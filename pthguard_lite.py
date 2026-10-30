#!/usr/bin/env python3
"""pthguard-lite: static scan of one Python site-packages/venv for .pth backdoors.

Single file, Python 3.8+ standard library only. Inspects files; never executes them.

    python -I -S pthguard_lite.py /path/to/venv/lib/python3.12/site-packages
    python -I -S pthguard_lite.py --help

Full version (RECORD hash checks, known-bad package list, multi-path / Docker
rootfs scans, JSON + CI exits, quarantine script):
https://py-forge.com/products/pthguard-python-backdoor-scanner?utm_source=github&utm_medium=code&utm_campaign=pthguard-lite
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

__version__ = "0.1.0"

# site.py only runs .pth lines that start with "import " / "import\t"
PTH_DANGEROUS_PATTERNS = [
    (re.compile(r"exec\s*\(", re.IGNORECASE), "Executable 'exec()' call found"),
    (re.compile(r"eval\s*\(", re.IGNORECASE), "Dynamic 'eval()' call found"),
    (re.compile(r"base64\.(?:b64decode|decode)", re.IGNORECASE), "Base64 payload decoding detected"),
    (re.compile(r"subprocess\.", re.IGNORECASE), "Subprocess / command execution attempt"),
    (re.compile(r"os\.system\s*\(", re.IGNORECASE), "Direct OS shell execution"),
    (re.compile(r"__import__\s*\(", re.IGNORECASE), "Obfuscated __import__() call"),
    (
        re.compile(r"\b(?:urllib\.request|urllib2|requests|socket|http\.client)\b", re.IGNORECASE),
        "Network / egress socket invocation",
    ),
]

# Common hooks written by virtualenv / setuptools / pip editable installs
BENIGN_PTH_LINES = [
    re.compile(r"^import _virtualenv\s*$"),
    re.compile(r"^import (__editable___[\w.]+_finder); \1\.install\([^()]*\)\s*$"),
    re.compile(
        r"^import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os\.environ\.get\(var, '\w+'\) == '\w+'; "
        r"enabled and __import__\('_distutils_hack'\)\.add_shim\(\); ?$"
    ),
    re.compile(
        r"^import sys, types, os;has_mfs = sys\.version_info > \(3, 5\);p = os\.path\.join\(sys\._getframe\(1\)\.f_locals\['sitedir'\]"
    ),
]

CUSTOMIZE_SUSPICIOUS_PATTERNS = [
    (re.compile(r"base64\.(?:b64decode|b85decode)", re.IGNORECASE), "Base64 decoding in startup hook"),
    (
        re.compile(r"subprocess\.(?:Popen|check_output|run|call)", re.IGNORECASE),
        "Subprocess spawning on startup",
    ),
    (
        re.compile(r"(?:OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|SSH_AUTH_SOCK|id_rsa)", re.IGNORECASE),
        "Credential harvesting target reference",
    ),
    (re.compile(r"socket\.(?:socket|create_connection)", re.IGNORECASE), "Network connection on startup"),
]


class LiteScanner:
    """Scan one tree for risky .pth / sitecustomize / usercustomize hooks."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.findings: List[Dict[str, Any]] = []
        self.pth_files = 0
        self.customize_files = 0

    def add_finding(
        self,
        severity: str,
        category: str,
        path: str,
        description: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.findings.append(
            {
                "severity": severity,
                "category": category,
                "path": path,
                "description": description,
                "details": details or {},
            }
        )

    def scan_pth_file(self, pth_path: pathlib.Path) -> None:
        self.pth_files += 1
        try:
            content = pth_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError) as exc:
            self.add_finding("MEDIUM", "UNREADABLE_FILE", str(pth_path), f"Cannot read .pth file: {exc}")
            return

        for idx, line in enumerate(content.splitlines(), start=1):
            stripped = line.rstrip()
            if not (stripped.startswith("import ") or stripped.startswith("import\t")):
                continue
            if any(b.search(stripped) for b in BENIGN_PTH_LINES):
                continue

            reason = next((r for pattern, r in PTH_DANGEROUS_PATTERNS if pattern.search(line)), None)
            if reason:
                self.add_finding(
                    "CRITICAL",
                    "MALICIOUS_PTH_HOOK",
                    str(pth_path),
                    f"Dangerous payload line {idx}: {reason}",
                    {"line_number": idx, "line_sample": line[:150]},
                )
            else:
                self.add_finding(
                    "MEDIUM",
                    "EXECUTABLE_PTH_LINE",
                    str(pth_path),
                    f"Line {idx} runs code at every Python startup (unrecognised hook, review it)",
                    {"line_number": idx, "line_sample": line[:150]},
                )

    def scan_customize_file(self, cust_path: pathlib.Path) -> None:
        self.customize_files += 1
        try:
            content = cust_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError) as exc:
            self.add_finding("MEDIUM", "UNREADABLE_FILE", str(cust_path), f"Cannot read file: {exc}")
            return

        for pattern, reason in CUSTOMIZE_SUSPICIOUS_PATTERNS:
            match = pattern.search(content)
            if match:
                self.add_finding(
                    "HIGH",
                    "SUSPICIOUS_CUSTOMIZE_HOOK",
                    str(cust_path),
                    f"Startup persistence risk: {reason}",
                    {"matched_token": match.group(0)},
                )

    def scan_path(self, root: pathlib.Path) -> None:
        if not root.exists():
            self.add_finding("LOW", "PATH_NOT_FOUND", str(root), "Specified scan target path does not exist")
            return

        if root.is_file():
            if root.suffix == ".pth":
                self.scan_pth_file(root)
            elif root.name in ("sitecustomize.py", "usercustomize.py"):
                self.scan_customize_file(root)
            return

        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            current = pathlib.Path(dirpath)
            for fname in filenames:
                fpath = current / fname
                if fname.endswith(".pth"):
                    self.scan_pth_file(fpath)
                elif fname in ("sitecustomize.py", "usercustomize.py"):
                    self.scan_customize_file(fpath)

    def run(self) -> Dict[str, Any]:
        self.scan_path(pathlib.Path(self.target).resolve())
        threats = sum(1 for f in self.findings if f["severity"] in ("HIGH", "CRITICAL"))
        return {
            "summary": {
                "target": self.target,
                "pth_files": self.pth_files,
                "customize_files": self.customize_files,
                "findings": len(self.findings),
                "threats_detected": threats,
            },
            "findings": self.findings,
        }


def format_text_report(results: Dict[str, Any]) -> str:
    summary = results["summary"]
    findings = results["findings"]
    lines = [
        "================================================================================",
        "                      PTHGUARD-LITE SCAN REPORT                                ",
        "================================================================================",
        f"Target                 : {summary['target']}",
        f".pth Files Inspected   : {summary['pth_files']}",
        f"Customize Hooks Found  : {summary['customize_files']}",
        f"Findings               : {summary['findings']}",
        f"Critical/High Threats  : {summary['threats_detected']}",
        "--------------------------------------------------------------------------------",
    ]
    if not findings:
        lines.append("[+] Status: CLEAN. No suspicious .pth or customize hooks detected.")
    else:
        lines.append(f"Findings ({len(findings)} total):")
        for i, f in enumerate(findings, start=1):
            lines.append(f"\n{i}. [{f['severity']}]  Category : {f['category']}")
            lines.append(f"   Path      : {f['path']}")
            lines.append(f"   Details   : {f['description']}")
            for k, v in f["details"].items():
                lines.append(f"               {k}: {v}")
    lines.append("================================================================================")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pthguard-lite",
        description=(
            "Static scan of one site-packages/venv path for risky .pth startup hooks "
            "and sitecustomize/usercustomize persistence. Stdlib only; never executes target code."
        ),
        epilog=(
            "Full version: https://py-forge.com/products/pthguard-python-backdoor-scanner"
            "?utm_source=github&utm_medium=cli&utm_campaign=pthguard-lite"
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "target",
        nargs="?",
        help="One site-packages, venv, or file (.pth / sitecustomize.py / usercustomize.py) to scan",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.target:
        build_parser().print_help()
        print("\nError: provide exactly one scan target path.", file=sys.stderr)
        return 2

    results = LiteScanner(args.target).run()
    print(format_text_report(results))
    # lite: print findings; exit 1 only when HIGH/CRITICAL so a quick check stays useful
    return 1 if results["summary"]["threats_detected"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
