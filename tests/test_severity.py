
from vulnexa.models.severity import (
    SEVERITY_ORDER,
    count_by_severity,
    filter_by_min_severity,
    is_at_least,
    is_valid_severity,
    severity_rank,
    sort_findings,
)


def test_severity_scale_is_ordered_least_to_most_severe():
    assert SEVERITY_ORDER == [
        "INFO",
        "LOW",
        "MEDIUM",
        "WARNING",
        "HIGH",
        "CRITICAL",
    ]


def test_severity_rank_increases_with_severity():
    assert severity_rank("INFO") < severity_rank("MEDIUM")
    assert severity_rank("MEDIUM") < severity_rank("WARNING")
    assert severity_rank("WARNING") < severity_rank("HIGH")
    assert severity_rank("HIGH") < severity_rank("CRITICAL")


def test_unknown_severity_does_not_raise():
    assert severity_rank("NOT-A-LEVEL") == 0
    assert is_valid_severity("NOT-A-LEVEL") is False


def test_is_at_least_boundary():
    assert is_at_least("HIGH", "HIGH") is True
    assert is_at_least("CRITICAL", "HIGH") is True
    assert is_at_least("MEDIUM", "HIGH") is False


def test_filter_by_min_severity(make_finding):
    findings = [
        make_finding(rule_id="R1", severity="WARNING"),
        make_finding(rule_id="R2", severity="HIGH"),
        make_finding(rule_id="R3", severity="INFO"),
    ]

    result = filter_by_min_severity(findings, "HIGH")

    assert [finding.rule_id for finding in result] == ["R2"]


def test_sort_findings_severity_first_then_position(make_finding):
    findings = [
        make_finding(rule_id="A", severity="WARNING", file_path="b.py", line_number=2),
        make_finding(rule_id="B", severity="CRITICAL", file_path="z.py", line_number=9),
        make_finding(rule_id="C", severity="WARNING", file_path="a.py", line_number=1),
    ]

    result = sort_findings(findings)

    assert [finding.rule_id for finding in result] == ["B", "C", "A"]


def test_count_by_severity_includes_zero_counts(make_finding):
    findings = [make_finding(severity="HIGH")]

    counts = count_by_severity(findings)

    assert counts["HIGH"] == 1
    assert counts["INFO"] == 0
    assert counts["CRITICAL"] == 0
