"""Hash integrity baseline manager and file tampering detection engine."""

import argparse
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional


def hash_file_sha256(path: str) -> Optional[str]:
    """Calculate SHA-256 digest of a file."""
    hasher = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None


def generate_directory_manifest(root_dir: str) -> Dict[str, str]:
    """Compute relative path SHA-256 mapping for all files under root directory."""
    manifest: Dict[str, str] = {}
    abs_root = os.path.abspath(root_dir)

    for root, _, files in os.walk(abs_root):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, abs_root)
            digest = hash_file_sha256(fpath)
            if digest:
                manifest[rel_path] = digest

    return manifest


def compare_manifests(baseline: Dict[str, str], current: Dict[str, str]) -> Dict[str, Any]:
    """Compare baseline manifest against current state to isolate tampering or changes."""
    added = [p for p in current if p not in baseline]
    removed = [p for p in baseline if p not in current]
    modified = [p for p in current if p in baseline and current[p] != baseline[p]]

    return {
        "tampering_detected": len(modified) > 0 or len(added) > 0 or len(removed) > 0,
        "modified_count": len(modified),
        "modified_files": modified,
        "added_count": len(added),
        "added_files": added,
        "removed_count": len(removed),
        "removed_files": removed,
    }


def execute_hash_integrity_baseline(
    directory: str = ".",
    baseline_file: Optional[str] = None,
    mode: str = "create",
) -> Dict[str, Any]:
    """Create directory integrity hash manifest or compare against existing baseline."""
    target_dir = os.path.abspath(directory)
    dest_baseline = os.path.abspath(baseline_file or os.path.join(target_dir, "integrity_manifest.json"))

    if mode == "create":
        manifest = generate_directory_manifest(target_dir)
        with open(dest_baseline, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        return {
            "status": "success",
            "mode": "create",
            "directory": target_dir,
            "baseline_file": dest_baseline,
            "total_files_hashed": len(manifest),
        }

    else:
        # Check / Verify mode
        if not os.path.isfile(dest_baseline):
            return {
                "status": "error",
                "message": f"Baseline file not found: {dest_baseline}",
            }

        with open(dest_baseline, "r", encoding="utf-8") as f:
            saved_manifest = json.load(f)

        current_manifest = generate_directory_manifest(target_dir)
        # Exclude the baseline file itself from comparison if inside target dir
        rel_baseline = os.path.relpath(dest_baseline, target_dir)
        saved_manifest.pop(rel_baseline, None)
        current_manifest.pop(rel_baseline, None)

        diff = compare_manifests(saved_manifest, current_manifest)

        return {
            "status": "success",
            "mode": "verify",
            "directory": target_dir,
            "baseline_file": dest_baseline,
            "baseline_files_count": len(saved_manifest),
            "current_files_count": len(current_manifest),
            **diff,
        }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for integrity baseline."""
    parser = argparse.ArgumentParser(
        description="Hash integrity baseline manager and file tampering detection engine."
    )
    parser.add_argument("--dir", "-d", default=".", help="Target directory to audit (default: current directory)")
    parser.add_argument("--baseline", "-b", help="Path to JSON baseline file")
    parser.add_argument(
        "--mode",
        "-m",
        choices=["create", "verify"],
        default="create",
        help="Operation mode (create new baseline or verify existing)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for integrity baseline."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_hash_integrity_baseline(
            directory=args.dir,
            baseline_file=args.baseline,
            mode=args.mode,
        )
        if result.get("status") == "error":
            sys.stderr.write(f"Error: {result.get('message')}\n")
            return 1

        if args.mode == "create":
            print(f"Created baseline: {result['baseline_file']} ({result['total_files_hashed']} files hashed)")
        else:
            tampered = result.get("tampering_detected")
            state_msg = "TAMPERING DETECTED" if tampered else "INTEGRITY VERIFIED CLEAN"
            print(f"Status: {state_msg}")
            print(f"Modified: {result['modified_count']} | Added: {result['added_count']} | Removed: {result['removed_count']}")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Integrity baseline error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
