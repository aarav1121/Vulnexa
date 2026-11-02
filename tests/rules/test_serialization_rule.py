
"""
Positive and negative test cases for VULN-003 (pickle).
"""

from vulnexa.rules.serialization import UnsafeDeserializationRule


def test_detects_pickle_loads(run_rule):
    findings = run_rule(
        UnsafeDeserializationRule(),
        "import pickle\nobj = pickle.loads(payload)\n",
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "VULN-003"
    assert findings[0].severity == "HIGH"
    assert findings[0].line_number == 2


def test_detects_pickle_load(run_rule):
    findings = run_rule(
        UnsafeDeserializationRule(),
        "import pickle\nwith open(path, 'rb') as f:\n    obj = pickle.load(f)\n",
    )

    assert len(findings) == 1
    assert findings[0].line_number == 3


def test_does_not_flag_json_loading(run_rule):
    findings = run_rule(
        UnsafeDeserializationRule(),
        "import json\nobj = json.loads(payload)\n",
    )

    assert findings == []


def test_does_not_flag_unrelated_module_load(run_rule):
    findings = run_rule(
        UnsafeDeserializationRule(),
        "import config\nsettings = config.load('settings.ini')\n",
    )

    assert findings == []
