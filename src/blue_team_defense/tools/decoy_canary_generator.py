"""Decoy canary generator for honeyfiles, beacon markers, and insider threat tripwires."""

import argparse
import json
import os
import secrets
import sys
from typing import Any, Dict, List, Optional


def generate_canary_content(file_type: str, canary_token: str) -> bytes:
    """Generate mock deceptive document containing canary callback identifier."""
    if file_type == "json":
        data = {
            "title": "Confidential Database Credentials - Production Replica",
            "environment": "Production-Internal",
            "canary_token": canary_token,
            "callback_endpoint": f"https://canary.internal.corp/audit?token={canary_token}",
            "users": [
                {"user": "admin_ops", "auth_hash": secrets.token_hex(16)},
                {"user": "svc_billing", "auth_hash": secrets.token_hex(16)},
            ],
        }
        return json.dumps(data, indent=2).encode("utf-8")

    elif file_type == "pdf":
        # Minimal valid PDF structure with embedded metadata tracking beacon
        pdf_raw = (
            f"%PDF-1.4\n"
            f"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
            f"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
            f"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >> endobj\n"
            f"4 0 obj << /Length 55 >> stream\n"
            f"BT /F1 12 Tf 72 712 Td (CONFIDENTIAL SALARY AUDIT - INTERNAL ONLY) ET\n"
            f"endstream endobj\n"
            f"5 0 obj << /CanaryToken ({canary_token}) /Beacon (https://canary.internal.corp/{canary_token}) >> endobj\n"
            f"xref\n0 6\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n0000000117 00000 n \n0000000213 00000 n \n0000000319 00000 n \n"
            f"trailer << /Size 6 /Root 1 0 R /Info 5 0 R >>\nstartxref\n410\n%%EOF"
        )
        return pdf_raw.encode("ascii")

    else:
        # Default text format
        text_content = (
            f"=== CONFIDENTIAL EXECUTIVE COMPENSATION REPORT ===\n"
            f"CLASSIFICATION: HIGHLY RESTRICTED\n"
            f"TRACKING IDENTIFIER: {canary_token}\n\n"
            f"This file is monitored by corporate security logging telemetry.\n"
            f"Beacon: https://canary.internal.corp/tripwire?id={canary_token}\n"
        )
        return text_content.encode("utf-8")


def execute_decoy_canary_generator(
    file_type: str = "pdf",
    output_path: Optional[str] = None,
    canary_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Generate honeyfile canary tripwire with embedded beacon tracking marker."""
    token = canary_token or f"CANARY-{secrets.token_hex(8).upper()}"
    clean_type = file_type.lower()
    if clean_type not in ("pdf", "json", "txt"):
        clean_type = "txt"

    payload_bytes = generate_canary_content(clean_type, token)

    dest_file = output_path
    if not dest_file:
        dest_file = f"confidential_audit_decoy.{clean_type}"

    abs_dest = os.path.abspath(dest_file)
    os.makedirs(os.path.dirname(abs_dest), exist_ok=True)

    with open(abs_dest, "wb") as f:
        f.write(payload_bytes)

    return {
        "status": "success",
        "file_type": clean_type,
        "canary_token": token,
        "output_path": abs_dest,
        "file_size_bytes": len(payload_bytes),
        "tracking_url": f"https://canary.internal.corp/audit?token={token}",
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for canary generator."""
    parser = argparse.ArgumentParser(
        description="Decoy canary generator for honeyfiles, beacon markers, and insider threat tripwires."
    )
    parser.add_argument(
        "--type",
        "-t",
        choices=["pdf", "json", "txt"],
        default="pdf",
        help="Canary document format (default: pdf)",
    )
    parser.add_argument("--output", "-o", help="Destination file path for generated decoy")
    parser.add_argument("--token", help="Custom tracking token identifier")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for canary generator."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_decoy_canary_generator(
            file_type=args.type,
            output_path=args.output,
            canary_token=args.token,
        )
        print(f"Decoy Honeyfile Generated: {result['output_path']}")
        print(f"Format: {result['file_type'].upper()} ({result['file_size_bytes']} bytes)")
        print(f"Tracking Token: {result['canary_token']}")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Canary generator error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
