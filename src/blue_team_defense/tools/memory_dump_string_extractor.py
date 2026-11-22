"""Memory dump and binary string extractor with pattern-based indicator filtering."""

import argparse
import os
import re
import sys
from typing import Any, Dict, List, Optional

ASCII_REGEX = re.compile(rb"[\x20-\x7E]{4,}")
UNICODE_REGEX = re.compile(rb"(?:[\x20-\x7E]\x00){4,}")


def extract_raw_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Extract both ASCII and UTF-16LE printable strings from binary payload."""
    results: List[str] = []

    # ASCII matches
    ascii_pat = re.compile(rb"[\x20-\x7E]{" + str(min_length).encode("ascii") + rb",}")
    for match in ascii_pat.finditer(data):
        results.append(match.group(0).decode("ascii", errors="replace"))

    # UTF-16LE Unicode matches
    uni_pat = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode("ascii") + rb",}")
    for match in uni_pat.finditer(data):
        raw = match.group(0)
        try:
            results.append(raw.decode("utf-16le", errors="replace"))
        except Exception:
            pass

    return results


def execute_memory_dump_string_extractor(
    file_path: str,
    min_length: int = 4,
    filter_regex: Optional[str] = None,
    max_results: int = 200,
) -> Dict[str, Any]:
    """Scan memory dump or binary image, extracting strings and categorizing IoC indicators."""
    if not os.path.isfile(file_path):
        return {
            "status": "error",
            "message": f"Target binary file not found: {file_path}",
        }

    with open(file_path, "rb") as f:
        data = f.read(2097152)  # Read up to 2MB

    raw_strings = extract_raw_strings(data, min_length=min_length)

    filtered_strings = raw_strings
    if filter_regex:
        pat = re.compile(filter_regex, re.IGNORECASE)
        filtered_strings = [s for s in raw_strings if pat.search(s)]

    # Categorize common IoCs
    urls: List[str] = []
    ips: List[str] = []
    executables: List[str] = []

    for s in raw_strings:
        if s.startswith(("http://", "https://")):
            urls.append(s)
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s):
            ips.append(s)
        elif s.lower().endswith((".exe", ".dll", ".sys", ".ps1", ".bat")):
            executables.append(s)

    return {
        "status": "success",
        "file_path": os.path.abspath(file_path),
        "total_extracted_strings": len(raw_strings),
        "filtered_count": len(filtered_strings),
        "sample_strings": filtered_strings[:max_results],
        "indicators": {
            "urls_found": list(set(urls))[:20],
            "ips_found": list(set(ips))[:20],
            "binaries_referenced": list(set(executables))[:20],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for memory string extractor."""
    parser = argparse.ArgumentParser(
        description="Memory dump and binary string extractor with pattern-based indicator filtering."
    )
    parser.add_argument("--file", "-f", required=True, help="Target memory dump or executable file to inspect")
    parser.add_argument("--min-len", "-m", type=int, default=4, help="Minimum string character length (default: 4)")
    parser.add_argument("--filter", help="Regex pattern to filter extracted strings")
    parser.add_argument("--limit", type=int, default=100, help="Maximum strings to output (default: 100)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for memory string extractor."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_memory_dump_string_extractor(
            file_path=args.file,
            min_length=args.min_len,
            filter_regex=args.filter,
            max_results=args.limit,
        )
        if result.get("status") == "error":
            sys.stderr.write(f"Error: {result.get('message')}\n")
            return 1

        print(f"File: {result['file_path']} | Total Strings: {result['total_extracted_strings']}")
        print(f"IoC Indicators: URLs={len(result['indicators']['urls_found'])}, IPs={len(result['indicators']['ips_found'])}, Binaries={len(result['indicators']['binaries_referenced'])}")
        return 0
    except Exception as exc:
        sys.stderr.write(f"String extractor error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
