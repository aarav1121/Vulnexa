
import ast

from vulnexa.analysis.taint_models import (
    CONDITION_SHELL_TRUE,
    SINK_CODE_EXECUTION,
    SINK_DESERIALIZATION,
    SINK_SHELL_COMMAND,
    TaintAnalysisResult,
    TaintFact,
    TaintFinding,
    TaintSink,
    TaintSource,
    TaintSanitizer,
    static_dotted_name,
)


def parse_expression(code: str):
    return ast.parse(code, mode="eval").body


def test_taint_fact_identity_is_value_based():
    fact_a = TaintFact(source_id="input", source_line=3)
    fact_b = TaintFact(source_id="input", source_line=3)

    assert fact_a == fact_b
    assert hash(fact_a) == hash(fact_b)
    assert len({fact_a, fact_b}) == 1


def test_taint_fact_distinguishes_origins():
    fact_a = TaintFact(source_id="input", source_line=3)
    fact_b = TaintFact(source_id="input", source_line=5)
    fact_c = TaintFact(source_id="sys.argv", source_line=3)

    assert fact_a != fact_b
    assert fact_a != fact_c
    assert len({fact_a, fact_b, fact_c}) == 3


def test_taint_fact_exemption_is_part_of_identity():
    plain = TaintFact(source_id="input", source_line=3)
    cleared = plain.with_cleared_sinks([SINK_SHELL_COMMAND])

    assert plain != cleared
    assert len({plain, cleared}) == 2


def test_fresh_fact_is_dangerous_for_every_sink_kind():
    fact = TaintFact(source_id="input", source_line=3)

    for sink_kind in (
        SINK_CODE_EXECUTION,
        SINK_SHELL_COMMAND,
        SINK_DESERIALIZATION,
    ):
        assert fact.is_exempt_for(sink_kind) is False
        assert fact.is_dangerous_for(sink_kind) is True


def test_with_cleared_sinks_preserves_origin_and_original():
    fact = TaintFact(source_id="input", source_line=3)

    cleared = fact.with_cleared_sinks([SINK_SHELL_COMMAND])

    assert cleared.source_id == "input"
    assert cleared.source_line == 3
    assert cleared.is_dangerous_for(SINK_SHELL_COMMAND) is False
    assert cleared.is_dangerous_for(SINK_DESERIALIZATION) is True
    assert fact.exempt_sinks == frozenset()


def test_union_semantics_sanitized_and_unsanitized_paths():
    origin = TaintFact(source_id="input", source_line=2)
    sanitized = origin.with_cleared_sinks([SINK_SHELL_COMMAND])

    state = {origin, sanitized}

    assert len(state) == 2
    assert any(
        fact.is_dangerous_for(SINK_SHELL_COMMAND) for fact in state
    )

    fully_cleared = sanitized.with_cleared_sinks([SINK_SHELL_COMMAND])
    assert fully_cleared == sanitized


def test_static_dotted_name_renders_name_and_attribute_chains():
    assert static_dotted_name(ast.parse("x", mode="eval").body) == "x"
    assert static_dotted_name(ast.parse("a.b.c", mode="eval").body) == "a.b.c"


def test_static_dotted_name_rejects_dynamic_bases():
    assert static_dotted_name(ast.parse("f().attr", mode="eval").body) is None
    assert static_dotted_name(ast.parse("items[0]", mode="eval").body) is None
    assert static_dotted_name(ast.parse("x.y()", mode="eval").body) is None


def test_call_name_matching_requires_bare_name_call():
    source = TaintSource(
        source_id="input",
        kind="standard-input",
        match_call_names=("input",),
    )

    assert source.matches(parse_expression("input()")) is True
    assert source.matches(parse_expression("print()")) is False
    assert source.matches(parse_expression("builtins.input()")) is False
    assert source.matches(parse_expression("input")) is False


def test_attribute_matching_requires_exact_dotted_path():
    source = TaintSource(
        source_id="sys.argv",
        kind="command-line",
        match_attribute_paths=("sys.argv",),
    )

    assert source.matches(parse_expression("sys.argv")) is True
    assert source.matches(parse_expression("config.sys.argv")) is False
    assert source.matches(parse_expression("sys")) is False


def test_sink_matches_call_nodes_only():
    sink = TaintSink(
        rule_id="TAINT-001",
        sink_kind=SINK_CODE_EXECUTION,
        title="t",
        severity="WARNING",
        message="m",
        recommendation="r",
        match_call_names=("eval",),
    )

    assert sink.matches(parse_expression("eval(x)")) is True
    assert sink.matches(parse_expression("eval")) is False


def test_sink_condition_shell_true_requires_literal_true():
    sink = TaintSink(
        rule_id="TAINT-003",
        sink_kind=SINK_SHELL_COMMAND,
        title="t",
        severity="HIGH",
        message="m",
        recommendation="r",
        match_attribute_paths=("subprocess.run",),
        condition=CONDITION_SHELL_TRUE,
    )

    assert sink.matches(parse_expression("subprocess.run(cmd, shell=True)")) is True
    assert sink.matches(parse_expression("subprocess.run(cmd)")) is False
    assert sink.matches(parse_expression("subprocess.run(cmd, shell=1)")) is False
    assert sink.matches(parse_expression("subprocess.run(cmd, shell=flag)")) is False


def test_unknown_condition_never_matches():
    sink = TaintSink(
        rule_id="TAINT-003",
        sink_kind=SINK_SHELL_COMMAND,
        title="t",
        severity="HIGH",
        message="m",
        recommendation="r",
        match_call_names=("run",),
        condition="nonexistent-condition",
    )

    assert sink.matches(parse_expression("run(cmd, shell=True)")) is False


def test_sanitizer_matching():
    sanitizer = TaintSanitizer(
        sanitizer_id="shlex.quote",
        clears_sinks=frozenset({SINK_SHELL_COMMAND}),
        match_attribute_paths=("shlex.quote",),
    )

    assert sanitizer.matches(parse_expression("shlex.quote(x)")) is True
    assert sanitizer.matches(parse_expression("pipes.quote(x)")) is False


def test_sink_create_finding_uses_fact_origin():
    node = parse_expression("os.system(cmd)")
    sink = TaintSink(
        rule_id="TAINT-002",
        sink_kind=SINK_SHELL_COMMAND,
        title="Tainted shell command",
        severity="HIGH",
        message="m",
        recommendation="r",
        match_attribute_paths=("os.system",),
    )
    fact = TaintFact(source_id="request.args", source_line=7)

    finding = sink.create_finding(
        node=node,
        file_path="app.py",
        function="run_report",
        fact=fact,
    )

    assert finding.rule_id == "TAINT-002"
    assert finding.title == "Tainted shell command"
    assert finding.severity == "HIGH"
    assert finding.file_path == "app.py"
    assert finding.function == "run_report"
    assert finding.sink_label == "os.system"
    assert finding.sink_line == 1
    assert finding.source_id == "request.args"
    assert finding.source_line == 7


def test_taint_finding_to_dict_includes_flow_fields():
    finding = TaintFinding(
        rule_id="TAINT-004",
        title="t",
        severity="HIGH",
        file_path="a.py",
        function="load",
        sink_label="pickle.loads",
        sink_line=10,
        source_id="sys.stdin",
        source_line=4,
        message="m",
        recommendation="r",
    )

    as_dict = finding.to_dict()

    assert as_dict == {
        "rule_id": "TAINT-004",
        "title": "t",
        "severity": "HIGH",
        "file_path": "a.py",
        "function": "load",
        "sink_label": "pickle.loads",
        "sink_line": 10,
        "source_id": "sys.stdin",
        "source_line": 4,
        "message": "m",
        "recommendation": "r",
    }


def test_taint_analysis_result_defaults():
    result = TaintAnalysisResult(file_path="a.py")

    assert result.findings == []
    assert result.to_dict() == {"file_path": "a.py", "findings": []}
