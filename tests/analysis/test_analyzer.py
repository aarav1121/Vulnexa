
from vulnexa.analysis import analyze_source


def test_analyze_source_combines_all_results():
    code = (
        "def helper(x):\n"
        "    return x\n"
        "\n"
        "class Service:\n"
        "    def run(self):\n"
        "        unused = 1\n"
        "        return helper(2)\n"
        "\n"
        "def broken():\n"
        "    print(ghost)\n"
    )

    result = analyze_source(code, file_path="test.py")

    assert result.symbols is not None
    assert result.scopes is not None
    assert result.hierarchy is not None

    assert "Service.run" in result.cfgs
    assert "Service.run" in result.dataflow

    # Scope analysis finds the undefined name.
    undefined = [issue.name for issue in result.scopes.undefined_references]
    assert "ghost" in undefined

    # Scope analysis finds the unused variable.
    unused = [issue.name for issue in result.scopes.unused_variables]
    assert "unused" in unused

    # Hierarchy links the caller to the callee.
    assert "helper" in result.hierarchy.functions["Service.run"].calls


def test_analyze_source_syntax_error_propagates():
    import pytest

    with pytest.raises(SyntaxError):
        analyze_source("def broken(:\n")


def test_analyze_source_includes_taint_results():
    code = (
        "u = input()\n"
        "eval(u)\n"
    )

    result = analyze_source(code, file_path="app.py")

    assert "<module>" in result.taint

    module_taint = result.taint["<module>"]
    findings = module_taint.findings
    assert len(findings) == 1

    finding = findings[0]
    assert finding.rule_id == "TAINT-001"
    assert finding.severity == "WARNING"
    assert finding.sink_label == "eval"
    assert finding.sink_line == 2
    assert finding.source_id == "input"
    assert finding.source_line == 1
    assert finding.function == "<module>"
    assert finding.file_path == "app.py"
    assert finding.message
    assert finding.recommendation


def test_analyze_source_clean_code_has_no_taint_findings():
    code = "x = 1\ny = x + 1\n"

    result = analyze_source(code, file_path="clean.py")

    findings = [
        finding
        for flow in result.taint.values()
        for finding in flow.findings
    ]

    assert findings == []
    assert result.taint["<module>"].function_name == "<module>"

