"""Unified Command Line Interface dispatcher for Blue Team Defense Toolkit."""

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

_src_dir = str(Path(__file__).resolve().parent.parent)
if _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)

from blue_team_defense.tools.phishing_link_defanger import build_parser as parse_defanger, main as main_defanger
from blue_team_defense.tools.file_entropy_triage import build_parser as parse_entropy, main as main_entropy
from blue_team_defense.tools.password_entropy_auditor import build_parser as parse_pwd, main as main_pwd
from blue_team_defense.tools.defender_posture_checker import build_parser as parse_posture, main as main_posture
from blue_team_defense.tools.yara_rule_scanner import build_parser as parse_yara, main as main_yara
from blue_team_defense.tools.decoy_canary_generator import build_parser as parse_canary, main as main_canary
from blue_team_defense.tools.hash_integrity_baseline import build_parser as parse_hash, main as main_hash
from blue_team_defense.tools.memory_dump_string_extractor import build_parser as parse_strings, main as main_strings
from blue_team_defense.tools.usb_storage_forensics import build_parser as parse_usb, main as main_usb
from blue_team_defense.tools.firewall_rule_auditor import build_parser as parse_firewall, main as main_firewall


def build_parser() -> argparse.ArgumentParser:
    """Build unified multi-command argument parser."""
    parser = argparse.ArgumentParser(
        prog="blueteam-cli",
        description="Blue Team Defense Toolkit: Endpoint forensics, malware triage, and defense CLI suite.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available defensive subcommands")

    subparsers.add_parser("defang", parents=[parse_defanger()], add_help=False, help="Defang URLs and strip tracking parameters")
    subparsers.add_parser("entropy", parents=[parse_entropy()], add_help=False, help="Analyze file block Shannon entropy")
    subparsers.add_parser("password", parents=[parse_pwd()], add_help=False, help="Audit password bit entropy and dictionaries")
    subparsers.add_parser("posture", parents=[parse_posture()], add_help=False, help="Inspect Windows Defender and firewall posture")
    subparsers.add_parser("yara", parents=[parse_yara()], add_help=False, help="Scan files against regex and byte signatures")
    subparsers.add_parser("canary", parents=[parse_canary()], add_help=False, help="Generate honeyfile decoy with tracking beacon")
    subparsers.add_parser("hash-baseline", parents=[parse_hash()], add_help=False, help="Create or verify SHA-256 directory baseline")
    subparsers.add_parser("strings", parents=[parse_strings()], add_help=False, help="Extract strings and IoCs from memory dumps")
    subparsers.add_parser("usb-forensics", parents=[parse_usb()], add_help=False, help="Audit historical USBSTOR connection logs")
    subparsers.add_parser("firewall", parents=[parse_firewall()], add_help=False, help="Audit firewall rules for permissive ports")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Unified CLI dispatch routine."""
    if argv is None:
        argv = sys.argv[1:]

    parser = build_parser()
    if not argv or argv[0] in ("-h", "--help"):
        parser.print_help()
        return 0

    command_map = {
        "defang": main_defanger,
        "entropy": main_entropy,
        "password": main_pwd,
        "posture": main_posture,
        "yara": main_yara,
        "canary": main_canary,
        "hash-baseline": main_hash,
        "strings": main_strings,
        "usb-forensics": main_usb,
        "firewall": main_firewall,
    }

    subcommand = argv[0]
    if subcommand in command_map:
        return command_map[subcommand](argv[1:])

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
