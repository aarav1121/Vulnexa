
"""
Positive and negative test cases for VULN-004 (os.system).
"""

from vulnexa.rules.command_execution import SystemCommandRule


def test_detects_os_system_call(run_rule):
    findings = run_rule(
        SystemCommandRule(),
        "import os\nos.system('echo ' + user_input)\n",
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "VULN-004"
    assert findings[0].severity == "HIGH"
    assert findings[0].line_number == 2


def test_does_not_flag_subprocess_system(run_rule):
    findings = run_rule(
        SystemCommandRule(),
        "import session\nsession.system('restart')\n",
    )

    assert findings == []


def test_does_not_flag_other_os_functions(run_rule):
    findings = run_rule(
        SystemCommandRule(),
        "import os\nos.getcwd()\nos.path.join(a, b)\n",
    )

    assert findings == []
