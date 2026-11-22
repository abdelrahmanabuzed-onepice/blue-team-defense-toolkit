"""Phishing link defanger, URL sanitization tool, and malicious pattern detector."""

import argparse
import re
import sys
import urllib.parse
from typing import Any, Dict, List, Optional


def defang_url_string(url_str: str) -> str:
    """Defang a URL to prevent accidental click-through execution."""
    # Replace protocols
    defanged = re.sub(r"^https://", "hxxps://", url_str, flags=re.IGNORECASE)
    defanged = re.sub(r"^http://", "hxxp://", defanged, flags=re.IGNORECASE)
    defanged = re.sub(r"^ftp://", "fxp://", defanged, flags=re.IGNORECASE)
    # Defang dots in domain/host
    parsed = urllib.parse.urlsplit(defanged)
    if parsed.netloc:
        defanged_netloc = parsed.netloc.replace(".", "[.]")
        defanged = defanged.replace(parsed.netloc, defanged_netloc, 1)
    else:
        defanged = defanged.replace(".", "[.]")
    return defanged


def strip_tracking_parameters(url_str: str) -> str:
    """Strip marketing and telemetry tracking query parameters from URL."""
    try:
        parsed = urllib.parse.urlsplit(url_str)
        if not parsed.query:
            return url_str
        query_dict = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        tracking_keys = {
            "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
            "gclid", "fbclid", "msclkid", "mc_eid", "yclid", "_hsenc", "_hsmi",
        }
        filtered = [(k, v) for k, v in query_dict if k.lower() not in tracking_keys]
        new_query = urllib.parse.urlencode(filtered)
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))
    except Exception:
        return url_str


def analyze_phishing_indicators(url_str: str) -> List[str]:
    """Inspect URL attributes for common phishing signatures."""
    indicators: List[str] = []
    url_lower = url_str.lower()

    # Check for credentials in URL (e.g. http://user:pass@domain)
    if "@" in url_str.split("?")[0]:
        indicators.append("Contains userinfo embedded in authority component (@ symbol)")

    # Check for punycode homograph attack
    if "xn--" in url_lower:
        indicators.append("Uses Punycode (potential IDN homograph attack)")

    # Check for raw IP address as domain host
    parsed = urllib.parse.urlsplit(url_str)
    host = parsed.hostname or ""
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        indicators.append("Host is a raw numerical IP address rather than a domain name")

    # Excessive subdomains
    if len(parts) > 4:
        indicators.append("Excessive subdomain depth (potential domain obfuscation)")

    # Suspicious brand keywords in path/subdomain
    suspicious_keywords = ["login", "verify", "secure", "account", "banking", "update", "signin"]
    if any(k in host for k in suspicious_keywords) and not any(k in parsed.path for k in suspicious_keywords):
        indicators.append("Contains high-value security keywords in hostname")

    return indicators


def execute_phishing_link_defanger(
    input_url: Optional[str] = None,
    text_content: Optional[str] = None,
    defang: bool = True,
    strip_tracking: bool = True,
) -> Dict[str, Any]:
    """Sanitize and analyze URLs or textual content containing links."""
    urls_to_process: List[str] = []

    if input_url:
        urls_to_process.append(input_url.strip())

    if text_content:
        found_urls = re.findall(r"https?://[^\s<>\"']+", text_content)
        urls_to_process.extend(found_urls)

    if not urls_to_process:
        urls_to_process = ["https://secure-login.verify-bank.com.fake/auth?utm_source=email&token=123"]

    processed_records: List[Dict[str, Any]] = []

    for orig_url in urls_to_process:
        sanitized = orig_url
        if strip_tracking:
            sanitized = strip_tracking_parameters(sanitized)

        indicators = analyze_phishing_indicators(orig_url)

        defanged_result = defang_url_string(sanitized) if defang else sanitized

        processed_records.append({
            "original": orig_url,
            "sanitized": sanitized,
            "defanged": defanged_result,
            "phishing_indicators": indicators,
            "risk_score": len(indicators) * 25,
            "is_suspicious": len(indicators) > 0,
        })

    return {
        "status": "success",
        "processed_count": len(processed_records),
        "suspicious_count": sum(1 for r in processed_records if r["is_suspicious"]),
        "records": processed_records,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for phishing defanger."""
    parser = argparse.ArgumentParser(
        description="Phishing link defanger, URL sanitizer, and malicious pattern detector."
    )
    parser.add_argument("--url", "-u", help="Individual target URL to defang and analyze")
    parser.add_argument("--text", "-t", help="Raw text containing links to extract and defang")
    parser.add_argument(
        "--no-strip-tracking",
        dest="strip_tracking",
        action="store_false",
        help="Retain marketing/analytics tracking parameters",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for phishing defanger."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_phishing_link_defanger(
            input_url=args.url,
            text_content=args.text,
            strip_tracking=args.strip_tracking,
        )
        print(f"Processed URLs: {result['processed_count']} (Flagged: {result['suspicious_count']})")
        for rec in result["records"]:
            print(f"  - Defanged: {rec['defanged']}")
            if rec["phishing_indicators"]:
                for ind in rec["phishing_indicators"]:
                    print(f"      [FLAG] {ind}")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Defanger error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
