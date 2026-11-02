
"""
Severity classification and handling for Vulnexa findings.

Severity levels are ordered from least to most severe so that
findings can be compared, sorted, and filtered consistently.
"""

from vulnexa.models.finding import Finding


# Severity levels ordered from least to most severe.
SEVERITY_ORDER = [
    "INFO",
    "LOW",
    "MEDIUM",
    "WARNING",
    "HIGH",
    "CRITICAL",
]

_SEVERITY_RANK = {
    severity: rank
    for rank, severity
    in enumerate(SEVERITY_ORDER)
}


def severity_rank(severity: str) -> int:
    """
    Return the numeric rank of a severity level.

    Unknown severity levels rank as 0 (treated like INFO)
    so that malformed metadata can never raise an error.
    """

    return _SEVERITY_RANK.get(severity, 0)


def is_valid_severity(severity: str) -> bool:
    """
    Check whether a severity level is part of the standard scale.
    """

    return severity in _SEVERITY_RANK


def is_at_least(severity: str, minimum: str) -> bool:
    """
    Check whether a severity level meets or exceeds a minimum level.
    """

    return severity_rank(severity) >= severity_rank(minimum)


def filter_by_min_severity(
    findings: list[Finding],
    minimum: str
) -> list[Finding]:
    """
    Return only findings whose severity meets the minimum level.
    """

    return [
        finding
        for finding in findings
        if is_at_least(finding.severity, minimum)
    ]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """
    Sort findings from most to least severe.

    Ties are broken by file path, then line number, then rule ID
    so that output order is stable and easy to review.
    """

    return sorted(
        findings,
        key=lambda finding: (
            -severity_rank(finding.severity),
            finding.file_path,
            finding.line_number,
            finding.rule_id
        )
    )


def count_by_severity(findings: list[Finding]) -> dict[str, int]:
    """
    Count findings per severity level, including zero counts.
    """

    counts = {severity: 0 for severity in SEVERITY_ORDER}

    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
        else:
            counts["UNKNOWN"] = counts.get("UNKNOWN", 0) + 1

    return counts
