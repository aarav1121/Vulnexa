
import pytest

from vulnexa.models.severity import severity_rank, sort_findings
from vulnexa.scanner import scan_directory, scan_file
from vulnexa.rules import create_default_registry


SAMPLES = "samples"
VULNERABLE_FILE = "samples/vulnerable/unsafe_eval.py"
SAFE_FILE = "samples/safe/safe_operations.py"


def test_scan_file_finds_eval_in_vulnerable_sample():
    findings = scan_file(VULNERABLE_FILE)

    rule_ids = [finding.rule_id for finding in findings]

    assert rule_ids == ["VULN-001"]
    assert findings[0].line_number == 3
    assert findings[0].file_path.replace("\\", "/").endswith(
        "samples/vulnerable/unsafe_eval.py"
    )


def test_scan_file_reports_nothing_for_safe_sample():
    findings = scan_file(SAFE_FILE)

    assert findings == []


def test_scan_file_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        scan_file("does_not_exist.py")


def test_scan_file_syntax_error_propagates(tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n", encoding="utf-8")

    with pytest.raises(SyntaxError):
        scan_file(broken)


def test_scan_directory_counts_samples():
    result = scan_directory(SAMPLES)

    assert result["files_found"] == 4
    assert result["files_scanned"] == 4
    assert result["errors"] == []


def test_scan_directory_reports_all_rule_families():
    result = scan_directory(SAMPLES)

    rule_ids = {finding.rule_id for finding in result["findings"]}

    assert {"VULN-001", "VULN-002", "VULN-003", "VULN-004", "VULN-005"} <= rule_ids


def test_scan_directory_collects_errors_and_continues(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "eval_only.py").write_text("eval('1')\n", encoding="utf-8")

    result = scan_directory(tmp_path)

    assert result["files_found"] == 2
    assert result["files_scanned"] == 1
    assert len(result["errors"]) == 1
    assert result["findings"][0].rule_id == "VULN-001"


def test_scan_directory_missing_dir_raises():
    with pytest.raises(NotADirectoryError):
        scan_directory("does_not_exist_dir")


def test_custom_registry_controls_detection(tmp_path):
    target = tmp_path / "code.py"
    target.write_text("eval('1')\nexec('2')\n", encoding="utf-8")

    registry = create_default_registry()
    registry.unregister("VULN-001")

    findings = scan_file(target, registry=registry)

    assert [finding.rule_id for finding in findings] == ["VULN-002"]


def test_directory_findings_are_sortable_by_severity():
    findings = scan_directory(SAMPLES)["findings"]

    ranked = [
        severity_rank(finding.severity)
        for finding in sort_findings(findings)
    ]

    assert ranked == sorted(ranked, reverse=True)
