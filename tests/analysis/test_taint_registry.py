
import ast

from vulnexa.analysis.taint_models import (
    SINK_CODE_EXECUTION,
    SINK_DESERIALIZATION,
    SINK_SHELL_COMMAND,
    TaintFact,
)
from vulnexa.analysis.taint_registry import (
    SANITIZERS,
    SINKS,
    SOURCES,
    get_sanitizers,
    get_sinks,
    get_sources,
    match_sanitizer,
    match_source,
    match_sinks,
)


def parse_expression(code: str):
    return ast.parse(code, mode="eval").body


def test_source_list_is_controlled():
    assert {source.source_id for source in SOURCES} == {
        "input",
        "sys.argv",
        "os.environ",
        "sys.stdin",
        "request.args",
        "request.form",
        "request.json",
    }


def test_every_source_declares_kind():
    for source in SOURCES:
        assert source.kind


def test_input_call_is_a_source():
    source = match_source(parse_expression("input()"))

    assert source is not None
    assert source.source_id == "input"
    assert match_source(parse_expression("input")) is None


def test_attribute_sources_match_exact_paths():
    cases = {
        "sys.argv": "sys.argv",
        "os.environ": "os.environ",
        "sys.stdin": "sys.stdin",
        "request.args": "request.args",
        "request.form": "request.form",
        "request.json": "request.json",
    }

    for source_id, code in cases.items():
        source = match_source(parse_expression(code))

        assert source is not None, code
        assert source.source_id == source_id, code


def test_framework_sources_reject_qualified_or_bound_bases():
    for code in (
        "flask.request.args",
        "self.request.args",
        "app.request.form",
        "api.request.json",
    ):
        assert match_source(parse_expression(code)) is None, code


def test_environ_and_request_accessors_found_via_walk():
    cases = {
        "os.environ.get('KEY')": "os.environ",
        "request.args.get('k')": "request.args",
        "sys.argv[1:]": "sys.argv",
    }

    for code, source_id in cases.items():
        expression = parse_expression(code)

        assert match_source(expression) is None, code

        matches = [
            match_source(node) for node in ast.walk(expression)
            if match_source(node) is not None
        ]
        assert len(matches) == 1, code
        assert matches[0].source_id == source_id, code


def test_variable_names_are_never_sources():
    for code in ("user_input", "request_data", "user_args", "payload"):
        assert match_source(parse_expression(code)) is None, code


def test_sink_rule_ids_kinds_and_severities():
    assert [sink.rule_id for sink in SINKS] == [
        "TAINT-001",
        "TAINT-002",
        "TAINT-003",
        "TAINT-004",
    ]
    assert [sink.sink_kind for sink in SINKS] == [
        SINK_CODE_EXECUTION,
        SINK_SHELL_COMMAND,
        SINK_SHELL_COMMAND,
        SINK_DESERIALIZATION,
    ]
    assert [sink.severity for sink in SINKS] == [
        "WARNING",
        "HIGH",
        "HIGH",
        "HIGH",
    ]

    for sink in SINKS:
        assert sink.title
        assert sink.message
        assert sink.recommendation


def test_eval_exec_and_pickle_sinks_match():
    cases = {
        "eval(x)": "TAINT-001",
        "exec(x)": "TAINT-001",
        "os.system(cmd)": "TAINT-002",
        "os.popen(cmd)": "TAINT-002",
        "pickle.load(f)": "TAINT-004",
        "pickle.loads(data)": "TAINT-004",
    }

    for code, rule_id in cases.items():
        matched = match_sinks(parse_expression(code))

        assert [sink.rule_id for sink in matched] == [rule_id], code


def test_qualified_builtin_eval_is_not_a_sink():
    assert match_sinks(parse_expression("builtins.eval(x)")) == ()


def test_subprocess_sink_requires_literal_shell_true():
    cases = (
        "subprocess.run(cmd, shell=True)",
        "subprocess.call(cmd, shell=True)",
        "subprocess.check_call(cmd, shell=True)",
        "subprocess.check_output(cmd, shell=True)",
        "subprocess.Popen(cmd, shell=True)",
    )

    for code in cases:
        matched = match_sinks(parse_expression(code))

        assert [sink.rule_id for sink in matched] == ["TAINT-003"], code

    assert match_sinks(parse_expression("subprocess.run(cmd)")) == ()
    assert match_sinks(parse_expression("subprocess.run(cmd, shell=1)")) == ()
    assert match_sinks(parse_expression("subprocess.run(cmd, shell=flag)")) == ()


def test_bare_run_is_not_a_subprocess_sink():
    assert match_sinks(parse_expression("run(cmd, shell=True)")) == ()


def test_sanitizer_list_is_exactly_shell_specific():
    assert {sanitizer.sanitizer_id for sanitizer in SANITIZERS} == {
        "shlex.quote",
        "shlex.join",
    }

    for sanitizer in SANITIZERS:
        assert sanitizer.clears_sinks == frozenset({SINK_SHELL_COMMAND})


def test_numeric_and_escaping_functions_are_not_sanitizers():
    for code in (
        "int(x)",
        "float(x)",
        "str(x)",
        "html.escape(x)",
        "urllib.parse.quote(x)",
    ):
        assert match_sanitizer(parse_expression(code)) is None, code


def test_shlex_sanitizers_match():
    quoted = match_sanitizer(parse_expression("shlex.quote(x)"))
    joined = match_sanitizer(parse_expression("shlex.join(parts)"))

    assert quoted is not None
    assert quoted.sanitizer_id == "shlex.quote"
    assert joined is not None
    assert joined.sanitizer_id == "shlex.join"


def test_shell_sanitization_clears_only_shell_sinks():
    fact = TaintFact(source_id="input", source_line=1)
    sanitizer = match_sanitizer(parse_expression("shlex.quote(x)"))

    cleared = fact.with_cleared_sinks(sanitizer.clears_sinks)

    assert cleared.is_exempt_for(SINK_SHELL_COMMAND) is True
    assert cleared.is_exempt_for(SINK_CODE_EXECUTION) is False
    assert cleared.is_exempt_for(SINK_DESERIALIZATION) is False


def test_accessors_expose_registry_tables():
    assert get_sources() == SOURCES
    assert get_sinks() == SINKS
    assert get_sanitizers() == SANITIZERS
