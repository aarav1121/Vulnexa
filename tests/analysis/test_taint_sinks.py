
import ast

from vulnexa.analysis.taint import analyze_taint
from vulnexa.rules import create_default_registry
from vulnexa.rules.engine import RuleEngine


def run_taint(code: str):
    return analyze_taint(ast.parse(code))


def test_tainted_eval_reports_code_execution():
    results = run_taint(
        "u = input()\n"
        "eval(u)\n"
    )

    findings = results["<module>"].findings
    assert len(findings) == 1

    finding = findings[0]
    assert finding.rule_id == "TAINT-001"
    assert finding.severity == "WARNING"
    assert finding.sink_label == "eval"
    assert finding.sink_line == 2
    assert finding.source_id == "input"
    assert finding.source_line == 1
    assert finding.function == "<module>"
    assert finding.message
    assert finding.recommendation


def test_tainted_exec_reports_code_execution():
    results = run_taint(
        "u = input()\n"
        "exec(u)\n"
    )

    findings = results["<module>"].findings
    assert [f.rule_id for f in findings] == ["TAINT-001"]
    assert findings[0].sink_label == "exec"
    assert findings[0].sink_line == 2


def test_tainted_os_system_and_popen_report_shell_sink():
    results = run_taint(
        "import os\n"
        "u = input()\n"
        "os.system('echo ' + u)\n"
        "os.popen(u)\n"
    )

    findings = results["<module>"].findings
    assert [f.rule_id for f in findings] == ["TAINT-002", "TAINT-002"]
    assert [f.sink_label for f in findings] == ["os.system", "os.popen"]
    assert [f.sink_line for f in findings] == [3, 4]
    assert all(f.source_id == "input" for f in findings)
    assert all(f.source_line == 2 for f in findings)
    assert all(f.severity == "HIGH" for f in findings)


def test_subprocess_shell_true_reports():
    results = run_taint(
        "import subprocess\n"
        "u = input()\n"
        "subprocess.run('ping ' + u, shell=True)\n"
        "subprocess.Popen(u, shell=True)\n"
    )

    findings = results["<module>"].findings
    assert [f.rule_id for f in findings] == ["TAINT-003", "TAINT-003"]
    assert [f.sink_label for f in findings] == [
        "subprocess.run",
        "subprocess.Popen",
    ]
    assert [f.sink_line for f in findings] == [3, 4]


def test_subprocess_without_shell_true_not_reported():
    results = run_taint(
        "import subprocess\n"
        "u = input()\n"
        "subprocess.run(['ping', u])\n"
        "subprocess.call(['ping', u])\n"
    )

    assert results["<module>"].findings == []


def test_tainted_pickle_reports_deserialization():
    results = run_taint(
        "import pickle\n"
        "u = input()\n"
        "obj = pickle.loads(u)\n"
        "obj2 = pickle.load(u)\n"
    )

    findings = results["<module>"].findings
    assert [f.rule_id for f in findings] == ["TAINT-004", "TAINT-004"]
    assert [f.sink_label for f in findings] == ["pickle.loads", "pickle.load"]
    assert [f.sink_line for f in findings] == [3, 4]


def test_clean_constants_produce_no_findings():
    results = run_taint(
        "eval('1 + 1')\n"
        "exec('x = 1')\n"
        "os.system('ls')\n"
        "subprocess.run('ls', shell=True)\n"
        "pickle.loads('data')\n"
    )

    assert results["<module>"].findings == []


def test_unrelated_source_produces_no_findings():
    results = run_taint(
        "u = input()\n"
        "x = len(u)\n"
        "eval('2 + 2')\n"
        "os.system('ls')\n"
    )

    assert results["<module>"].findings == []


def test_multiple_sources_produce_distinct_findings():
    results = run_taint(
        "a = input()\n"
        "b = sys.argv\n"
        "os.system(a + b)\n"
    )

    findings = results["<module>"].findings
    assert len(findings) == 2
    assert {f.source_id for f in findings} == {"input", "sys.argv"}
    assert {f.source_line for f in findings} == {1, 2}
    assert all(f.rule_id == "TAINT-002" for f in findings)
    assert all(f.sink_line == 3 for f in findings)


def test_loop_flow_reported_once():
    results = run_taint(
        "u = input()\n"
        "for _ in range(3):\n"
        "    eval(u)\n"
    )

    findings = results["<module>"].findings
    assert len(findings) == 1
    assert findings[0].sink_line == 3


def test_sanitized_shell_flow_not_reported():
    results = run_taint(
        "import shlex\n"
        "u = input()\n"
        "q = shlex.quote(u)\n"
        "os.system('echo ' + q)\n"
        "os.system(shlex.quote(u))\n"
    )

    assert results["<module>"].findings == []


def test_sanitization_does_not_suppress_other_sinks():
    results = run_taint(
        "u = input()\n"
        "q = shlex.quote(u)\n"
        "eval(q)\n"
        "pickle.loads(q)\n"
    )

    findings = results["<module>"].findings
    assert [(f.rule_id, f.sink_line) for f in findings] == [
        ("TAINT-001", 3),
        ("TAINT-004", 4),
    ]


def test_from_import_sinks_match():
    results = run_taint(
        "from os import system\n"
        "from pickle import loads\n"
        "u = input()\n"
        "system('echo ' + u)\n"
        "loads(u)\n"
    )

    findings = results["<module>"].findings
    assert [(f.rule_id, f.sink_line) for f in findings] == [
        ("TAINT-002", 4),
        ("TAINT-004", 5),
    ]


def test_module_alias_sinks_match():
    results = run_taint(
        "import subprocess as sp\n"
        "u = input()\n"
        "sp.Popen(u, shell=True)\n"
    )

    findings = results["<module>"].findings
    assert [f.rule_id for f in findings] == ["TAINT-003"]
    assert findings[0].sink_label == "sp.Popen"
    assert findings[0].sink_line == 3


def test_sanitizer_alias_matches():
    results = run_taint(
        "from shlex import quote as sq\n"
        "u = input()\n"
        "os.system(sq(u))\n"
    )

    assert results["<module>"].findings == []


def test_unregistered_bare_names_not_matched():
    results = run_taint(
        "u = input()\n"
        "run(u, shell=True)\n"
        "system(u)\n"
        "loads(u)\n"
    )

    assert results["<module>"].findings == []


def test_star_import_aliases_not_matched():
    results = run_taint(
        "from os import *\n"
        "u = input()\n"
        "system(u)\n"
    )

    assert results["<module>"].findings == []


def test_findings_carry_function_file_and_serialization():
    code = (
        "def handler():\n"
        "    u = input()\n"
        "    eval(u)\n"
    )

    results = analyze_taint(
        ast.parse(code),
        file_path="app.py",
    )

    findings = results["handler"].findings
    assert len(findings) == 1

    finding = findings[0]
    assert finding.file_path == "app.py"
    assert finding.function == "handler"
    assert finding.sink_label == "eval"

    as_dict = finding.to_dict()
    assert as_dict["rule_id"] == "TAINT-001"
    assert as_dict["file_path"] == "app.py"
    assert as_dict["function"] == "handler"
    assert as_dict["sink_label"] == "eval"
    assert as_dict["sink_line"] == 3
    assert as_dict["source_id"] == "input"
    assert as_dict["source_line"] == 2


def test_findings_ordering_is_deterministic():
    code = (
        "u = input()\n"
        "v = sys.argv\n"
        "exec(v)\n"
        "eval(u)\n"
        "os.system(u)\n"
    )

    first = run_taint(code)["<module>"].findings
    second = run_taint(code)["<module>"].findings

    assert first == second
    assert [(f.rule_id, f.sink_line) for f in first] == [
        ("TAINT-001", 3),
        ("TAINT-001", 4),
        ("TAINT-002", 5),
    ]


def test_taint_findings_separate_from_vuln_rules():
    code = (
        "import os\n"
        "u = input()\n"
        "os.system('echo ' + u)\n"
    )

    engine = RuleEngine(create_default_registry())
    vuln_findings = engine.analyze(ast.parse(code), file_path="a.py")
    assert [f.rule_id for f in vuln_findings] == ["VULN-004"]

    taint_findings = run_taint(code)["<module>"].findings
    assert [f.rule_id for f in taint_findings] == ["TAINT-002"]
