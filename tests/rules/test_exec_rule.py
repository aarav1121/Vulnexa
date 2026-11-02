
"""
Positive and negative test cases for VULN-002 (exec).
"""

from vulnexa.rules.insecure_functions import ExecRule


def test_detects_direct_exec_call(run_rule):
    findings = run_rule(ExecRule(), "exec(user_code)\n")

    assert len(findings) == 1
    assert findings[0].rule_id == "VULN-002"
    assert findings[0].severity == "WARNING"
    assert findings[0].line_number == 1


def test_detects_exec_inside_function(run_rule):
    code = (
        "def bootstrap(code_str):\n"
        "    exec(code_str)\n"
    )

    findings = run_rule(ExecRule(), code)

    assert len(findings) == 1
    assert findings[0].function == "bootstrap"


def test_does_not_flag_other_calls(run_rule):
    code = (
        "execute(plan)\n"
        "evaluate(x)\n"
        "print('done')\n"
    )

    findings = run_rule(ExecRule(), code)

    assert findings == []
