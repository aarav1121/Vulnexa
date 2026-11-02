
"""
Positive and negative test cases for VULN-005 (subprocess shell=True).
"""

from vulnexa.rules.subprocess_shell import SubprocessShellRule


def test_detects_run_with_shell_true(run_rule):
    findings = run_rule(
        SubprocessShellRule(),
        "import subprocess\nsubprocess.run('ping ' + host, shell=True)\n",
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "VULN-005"
    assert findings[0].severity == "HIGH"
    assert findings[0].line_number == 2


def test_detects_popen_with_shell_true(run_rule):
    findings = run_rule(
        SubprocessShellRule(),
        "import subprocess\nsubprocess.Popen(cmd, shell=True)\n",
    )

    assert len(findings) == 1


def test_shell_false_is_not_flagged(run_rule):
    findings = run_rule(
        SubprocessShellRule(),
        "import subprocess\nsubprocess.run(['ping', host], shell=False)\n",
    )

    assert findings == []


def test_omitting_shell_is_not_flagged(run_rule):
    findings = run_rule(
        SubprocessShellRule(),
        "import subprocess\nsubprocess.run(['ping', host])\n",
    )

    assert findings == []


def test_other_modules_with_shell_kwarg_are_not_flagged(run_rule):
    findings = run_rule(
        SubprocessShellRule(),
        "import renderer\nrenderer.run(template, shell=True)\n",
    )

    assert findings == []
