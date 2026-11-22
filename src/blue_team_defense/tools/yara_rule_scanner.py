"""YARA-style byte and regex pattern scanner for file signature matching and malware triage."""

import argparse
import os
import re
import sys
from typing import Any, Dict, List, Optional

DEFAULT_SIGNATURES = [
    {
        "id": "SUSP_POWERSHELL_DOWNLOAD",
        "name": "PowerShell Web Download C2 Cradle",
        "type": "regex",
        "pattern": r"(?i)(DownloadString|DownloadFile|IEX\s*\(New-Object\s*Net\.WebClient\))",
        "severity": "HIGH",
    },
    {
        "id": "SUSP_BASE64_PE_HEADER",
        "name": "Base64 Encoded PE Executable Header",
        "type": "regex",
        "pattern": r"TVqQAAMAAAAEAAAA",
        "severity": "CRITICAL",
    },
    {
        "id": "SUSP_OBFUSCATED_CMD",
        "name": "Environment Variable Obfuscated CMD",
        "type": "regex",
        "pattern": r"(?i)cmd\.exe\s+/c\s*\"%[a-z0-9_]+%",
        "severity": "MEDIUM",
    },
    {
        "id": "MAGIC_WINDOWS_PE",
        "name": "Windows Portable Executable MZ Signature",
        "type": "bytes",
        "pattern": b"MZ",
        "severity": "INFO",
    },
]


def scan_file_for_signatures(file_path: str, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Scan a single binary or text file for regex and byte patterns."""
    hits: List[Dict[str, Any]] = []
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read(1048576)  # Read up to 1MB per file
        text_content = raw_bytes.decode("latin-1", errors="replace")

        for sig in signatures:
            sig_type = sig.get("type", "regex")
            if sig_type == "bytes":
                pattern_bytes = sig["pattern"] if isinstance(sig["pattern"], bytes) else sig["pattern"].encode("latin-1")
                idx = raw_bytes.find(pattern_bytes)
                if idx != -1:
                    hits.append({
                        "signature_id": sig["id"],
                        "name": sig["name"],
                        "severity": sig["severity"],
                        "match_offset": idx,
                    })
            else:
                regex_str = sig["pattern"]
                match = re.search(regex_str, text_content)
                if match:
                    hits.append({
                        "signature_id": sig["id"],
                        "name": sig["name"],
                        "severity": sig["severity"],
                        "match_offset": match.start(),
                        "snippet": match.group(0)[:60],
                    })
    except (OSError, PermissionError):
        pass

    return hits


def execute_yara_rule_scanner(
    target_dir: str = ".",
    signatures: Optional[List[Dict[str, Any]]] = None,
    max_depth: int = 3,
) -> Dict[str, Any]:
    """Scan directory tree against YARA-style byte and regex threat signatures."""
    rules = signatures or DEFAULT_SIGNATURES
    abs_root = os.path.abspath(target_dir)

    total_scanned_files = 0
    matched_files: List[Dict[str, Any]] = []
    root_depth = abs_root.rstrip(os.path.sep).count(os.path.sep)

    for root, _, files in os.walk(abs_root):
        curr_depth = root.count(os.path.sep) - root_depth
        if curr_depth > max_depth:
            continue

        for fname in files:
            fpath = os.path.join(root, fname)
            total_scanned_files += 1
            findings = scan_file_for_signatures(fpath, rules)
            if findings:
                matched_files.append({
                    "file_path": fpath,
                    "matches_count": len(findings),
                    "matches": findings,
                })

    return {
        "status": "success",
        "scan_directory": abs_root,
        "rules_active_count": len(rules),
        "total_scanned_files": total_scanned_files,
        "flagged_files_count": len(matched_files),
        "flagged_files": matched_files,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for YARA scanner."""
    parser = argparse.ArgumentParser(
        description="YARA-style byte and regex pattern scanner for file threat signature triage."
    )
    parser.add_argument("--dir", "-d", default=".", help="Root directory path to scan (default: current directory)")
    parser.add_argument("--depth", type=int, default=3, help="Maximum subdirectory traversal depth (default: 3)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for YARA scanner."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_yara_rule_scanner(
            target_dir=args.dir,
            max_depth=args.depth,
        )
        print(f"Directory: {result['scan_directory']} | Rules Applied: {result['rules_active_count']}")
        print(f"Scanned Files: {result['total_scanned_files']} (Threat Flagged: {result['flagged_files_count']})")
        for f in result["flagged_files"]:
            print(f"  - {f['file_path']} ({f['matches_count']} matches)")
            for m in f["matches"]:
                print(f"      [{m['severity']}] {m['name']} at offset {m['match_offset']}")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Signature scanner error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
