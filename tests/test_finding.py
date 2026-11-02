
from vulnexa.models.finding import Finding


def make_finding(**overrides):
    """
    Build a Finding with sensible defaults for testing.
    """

    defaults = dict(
        rule_id="VULN-001",
        title="Use of eval()",
        severity="WARNING",
        file_path="test.py",
        line_number=1,
        message="message",
        recommendation="recommendation",
        function="eval",
    )

    defaults.update(overrides)
    return Finding(**defaults)


def test_finding_fields_are_stored():
    finding = make_finding()

    assert finding.rule_id == "VULN-001"
    assert finding.title == "Use of eval()"
    assert finding.severity == "WARNING"
    assert finding.file_path == "test.py"
    assert finding.line_number == 1
    assert finding.function == "eval"


def test_to_dict_contains_all_fields():
    finding = make_finding()
    result = finding.to_dict()

    assert result == {
        "rule_id": "VULN-001",
        "title": "Use of eval()",
        "severity": "WARNING",
        "file_path": "test.py",
        "line_number": 1,
        "message": "message",
        "recommendation": "recommendation",
        "function": "eval",
    }
