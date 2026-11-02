
"""
Positive and negative test cases for VULN-001 (eval).
"""

from vulnexa.rules.insecure_functions import EvalRule


def test_detects_direct_eval_call(run_rule):
    findings = run_rule(EvalRule(), "result = eval(user_input)\n")

    assert len(findings) == 1
    assert findings[0].rule_id == "VULN-001"
    assert findings[0].severity == "WARNING"
    assert findings[0].line_number == 1


def test_detects_eval_inside_function(run_rule):
    code = (
        "def run(data):\n"
        "    return eval(data)\n"
    )

    findings = run_rule(EvalRule(), code)

    assert len(findings) == 1
    assert findings[0].function == "run"


def test_does_not_flag_safe_functions(run_rule):
    code = (
        "value = int('42')\n"
        "result = eval  # reference without call\n"
        "print(result)\n"
    )

    findings = run_rule(EvalRule(), code)

    assert findings == []


def test_does_not_flag_attribute_eval(run_rule):
    findings = run_rule(
        EvalRule(),
        "import builtins\nbuiltins.eval('1')\n",
    )

    assert findings == []
