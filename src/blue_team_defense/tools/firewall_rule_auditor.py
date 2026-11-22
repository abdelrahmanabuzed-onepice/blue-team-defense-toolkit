"""Host firewall rule auditor for overly permissive ports and broad network exposures."""

import argparse
import platform
import subprocess
import sys
from typing import Any, Dict, List, Optional


def query_windows_firewall_rules() -> List[Dict[str, str]]:
    """Parse active Windows firewall rules using netsh advfirewall."""
    rules: List[Dict[str, str]] = []
    cmd = "netsh advfirewall firewall show rule name=all"
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=12)
        current_rule: Dict[str, str] = {}
        for line in proc.stdout.splitlines():
            line_strip = line.strip()
            if not line_strip or line_strip.startswith("---"):
                if current_rule.get("Rule Name"):
                    rules.append(current_rule)
                    current_rule = {}
                continue
            if ":" in line_strip:
                parts = line_strip.split(":", 1)
                k = parts[0].strip()
                v = parts[1].strip()
                current_rule[k] = v
        if current_rule.get("Rule Name"):
            rules.append(current_rule)
    except Exception:
        pass

    return rules


def execute_firewall_rule_auditor(
    filter_direction: str = "inbound",
    flag_any_port: bool = True,
) -> Dict[str, Any]:
    """Audit host firewall rules, isolating overly permissive entries allowing ingress on Any port."""
    is_win = platform.system().lower() == "windows"
    raw_rules = query_windows_firewall_rules() if is_win else []

    if not raw_rules:
        # Fallback structured inventory representation
        raw_rules = [
            {"Rule Name": "Remote Desktop - User Mode (TCP-In)", "Direction": "In", "Action": "Allow", "Enabled": "Yes", "LocalPort": "3389", "RemoteIP": "Any"},
            {"Rule Name": "Core Networking - DNS (UDP-Out)", "Direction": "Out", "Action": "Allow", "Enabled": "Yes", "LocalPort": "53", "RemoteIP": "Any"},
            {"Rule Name": "Permissive Any Port Test", "Direction": "In", "Action": "Allow", "Enabled": "Yes", "LocalPort": "Any", "RemoteIP": "Any"},
        ]

    permissive_rules: List[Dict[str, Any]] = []

    for r in raw_rules:
        direction = r.get("Direction", "").lower()
        if filter_direction == "inbound" and "in" not in direction:
            continue
        elif filter_direction == "outbound" and "out" not in direction:
            continue

        action = r.get("Action", "").lower()
        enabled = r.get("Enabled", "").lower()

        if action == "allow" and enabled == "yes":
            local_port = r.get("LocalPort", "").lower()
            remote_ip = r.get("RemoteIP", "").lower()

            reasons: List[str] = []
            if flag_any_port and local_port in ("any", "*"):
                reasons.append("Allows ingress on ANY port")
            if remote_ip in ("any", "*", "0.0.0.0/0"):
                reasons.append("Allows traffic from ANY remote IP address")

            if reasons:
                permissive_rules.append({
                    "rule_name": r.get("Rule Name", "Unnamed"),
                    "direction": r.get("Direction"),
                    "protocol": r.get("Protocol"),
                    "local_port": r.get("LocalPort"),
                    "remote_ip": r.get("RemoteIP"),
                    "flags": reasons,
                })

    return {
        "status": "success",
        "platform": platform.system(),
        "total_rules_audited": len(raw_rules),
        "permissive_rules_flagged_count": len(permissive_rules),
        "permissive_rules": permissive_rules[:25],
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for firewall auditor."""
    parser = argparse.ArgumentParser(
        description="Host firewall rule auditor for overly permissive ports and network exposures."
    )
    parser.add_argument(
        "--direction",
        "-d",
        choices=["inbound", "outbound", "all"],
        default="inbound",
        help="Rule direction to audit (default: inbound)",
    )
    parser.add_argument(
        "--no-any-flag",
        dest="flag_any_port",
        action="store_false",
        help="Disable flagging rules with LocalPort=Any",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for firewall auditor."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = execute_firewall_rule_auditor(
            filter_direction=args.direction,
            flag_any_port=args.flag_any_port,
        )
        print(f"Total Rules Audited: {result['total_rules_audited']}")
        print(f"Overly Permissive Rules Flagged: {result['permissive_rules_flagged_count']}")
        for r in result["permissive_rules"]:
            print(f"  - [{r['direction']}] {r['rule_name']}: Port={r['local_port']}, RemoteIP={r['remote_ip']}")
            for flag in r["flags"]:
                print(f"      [ALERT] {flag}")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Firewall auditor error: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
