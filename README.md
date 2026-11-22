# Blue Team Defense Toolkit

A modular Python defensive engineering and endpoint security forensics suite designed for threat triage, integrity baseline monitoring, malware entropy analysis, and perimeter auditing.

## Architecture

```text
[ Host & Artifact Ingestion ]
  │   ├── Untrusted Files, Binaries & Process Memory Images
  │   ├── Suspicious URLs & Inbound Phishing Payloads
  │   └── Host Subsystems (Windows Defender, Firewall, Registry)
  ▼
[ Defensive Analysis & Forensics Processing ]
  │   ├── Phishing Link Defanger & Parameter Sanitizer
  │   ├── Chunked Shannon Entropy Block Triager
  │   ├── Password Entropy & Dictionary Defense Evaluator
  │   ├── Windows Defender & Host Firewall Posture Inspector
  │   ├── YARA Byte & Regex Signature Scanning Engine
  │   ├── Honeyfile Tripwire & Decoy Canary Generator
  │   ├── SHA-256 Directory Cryptographic Hash Baselines
  │   ├── Memory Dump & Binary String IoC Extractor
  │   ├── USB Mass Storage Insertion Forensics
  │   └── Ingress Firewall Rule Exposure Auditor
  ▼
[ Incident Response Targets ]
  ├── Real-time Operator Security Alerts
  ├── Forensic Verification Artifacts
  └── Structured Integrity Diffs & Tampering Logs
```

## Tool Inventory

| Tool | Module | Description |
|---|---|---|
| Phishing Defanger | `phishing_link_defanger.py` | Defangs URLs (`hxxp://`, `[.]`), strips tracking tokens, and flags suspicious indicators |
| File Entropy Triage | `file_entropy_triage.py` | Computes chunked Shannon entropy to isolate packed, encrypted, or compressed payloads |
| Password Entropy Auditor | `password_entropy_auditor.py` | Measures password entropy in bits, detects dictionary patterns, and generates secure credentials |
| Defender Posture Checker | `defender_posture_checker.py` | Audits Windows Defender real-time protection and firewall profile state |
| YARA Rule Scanner | `yara_rule_scanner.py` | Matches byte signatures and regex threat patterns across directories and binaries |
| Decoy Canary Generator | `decoy_canary_generator.py` | Generates tripwire honeyfiles (PDF, JSON, TXT) with embedded tracking markers |
| Hash Integrity Baseline | `hash_integrity_baseline.py` | Establishes SHA-256 directory baselines to isolate file tampering, modifications, or additions |
| Memory String Extractor | `memory_dump_string_extractor.py` | Extracts ASCII and Unicode strings from binaries with IoC categorization (IPs, URLs, EXEs) |
| USB Storage Forensics | `usb_storage_forensics.py` | Scans USBSTOR registry hives to trace historical external storage device connections |
| Firewall Rule Auditor | `firewall_rule_auditor.py` | Scans host firewall configurations for overly broad ports and exposed ingress rules |

## Quickstart

### Installation

```bash
git clone https://github.com/abdelrahmanabuzed-onepice/blue-team-defense-toolkit.git
cd blue-team-defense-toolkit
pip install -e .
```

### Usage Examples

Run via unified CLI dispatcher:

```bash
# Display CLI help
blueteam-cli --help

# Defang suspicious URLs
blueteam-cli defang --url "https://login-verify.example.fake/update?utm_source=phish"

# Triage file entropy
blueteam-cli entropy --file suspicious_binary.bin

# Establish cryptographic hash baseline
blueteam-cli hash-baseline --dir C:\critical_app --mode create
```

Or execute individual tool scripts directly:

```bash
python src/blue_team_defense/tools/password_entropy_auditor.py --password "P@ssw0rd123"
```

## Testing

Execute the unit test suite using pytest:

```bash
pytest tests/
```

## Author

Abdelrahman Abouzed  
GitHub: [abdelrahmanabuzed-onepice](https://github.com/abdelrahmanabuzed-onepice)
