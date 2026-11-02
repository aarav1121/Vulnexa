
import ast

from vulnexa.analysis.taint import analyze_taint
from vulnexa.analysis.taint_models import (
    SINK_CODE_EXECUTION,
    SINK_DESERIALIZATION,
    SINK_SHELL_COMMAND,
    TaintFact,
)


def run_taint(code: str):
    return analyze_taint(ast.parse(code))


def test_input_source_seeds_taint():
    results = run_taint("x = input()\n")

    assert results["<module>"].facts_for("x") == {
        TaintFact(source_id="input", source_line=1)
    }


def test_attribute_sources_seed_taint():
    results = run_taint(
        "args = sys.argv\n"
        "env = os.environ\n"
        "stream = sys.stdin\n"
        "plain = user_input\n"
    )

    module = results["<module>"]

    assert module.facts_for("args") == {TaintFact("sys.argv", 1)}
    assert module.facts_for("env") == {TaintFact("os.environ", 2)}
    assert module.facts_for("stream") == {TaintFact("sys.stdin", 3)}
    assert module.facts_for("plain") == frozenset()


def test_chained_assignment_propagates():
    results = run_taint(
        "a = input()\n"
        "b = a\n"
        "c = b\n"
    )

    expected = {TaintFact("input", 1)}
    module = results["<module>"]

    assert module.facts_for("a") == expected
    assert module.facts_for("b") == expected
    assert module.facts_for("c") == expected


def test_clean_reassignment_clears_taint():
    results = run_taint(
        "x = input()\n"
        "x = 'safe'\n"
    )

    assert results["<module>"].facts_for("x") == frozenset()


def test_reassignment_preserves_copied_taint():
    results = run_taint(
        "x = input()\n"
        "y = x\n"
        "x = 1\n"
    )

    module = results["<module>"]

    assert module.facts_for("y") == {TaintFact("input", 1)}
    assert module.facts_for("x") == frozenset()


def test_binary_operations_and_formatting_propagate():
    results = run_taint(
        "u = input()\n"
        "a = 'pre' + u\n"
        "b = f'v={u}'\n"
        "c = '%s' % u\n"
        "d = '{}'.format(u)\n"
    )

    expected = {TaintFact("input", 1)}
    module = results["<module>"]

    assert module.facts_for("a") == expected
    assert module.facts_for("b") == expected
    assert module.facts_for("c") == expected
    assert module.facts_for("d") == expected


def test_subscript_and_attribute_reads_propagate():
    results = run_taint(
        "u = input()\n"
        "a = u['k']\n"
        "b = u.value\n"
        "c = settings.debug\n"
    )

    module = results["<module>"]

    assert module.facts_for("a") == {TaintFact("input", 1)}
    assert module.facts_for("b") == {TaintFact("input", 1)}
    assert module.facts_for("c") == frozenset()


def test_unknown_call_propagates_argument_taint():
    results = run_taint(
        "u = input()\n"
        "a = transform(u)\n"
        "b = obj.prepare(u)\n"
        "c = len(u)\n"
    )

    expected = {TaintFact("input", 1)}
    module = results["<module>"]

    assert module.facts_for("a") == expected
    assert module.facts_for("b") == expected
    assert module.facts_for("c") == expected


def test_augmented_assignment_propagates():
    results = run_taint(
        "u = input()\n"
        "log = 'entries: '\n"
        "log += u\n"
    )

    assert results["<module>"].facts_for("log") == {TaintFact("input", 1)}


def test_walrus_assignment_propagates():
    results = run_taint("y = (x := input())\n")

    module = results["<module>"]
    expected = {TaintFact("input", 1)}

    assert module.facts_for("x") == expected
    assert module.facts_for("y") == expected


def test_for_target_propagates():
    results = run_taint(
        "for a in sys.argv:\n"
        "    x = a\n"
    )

    module = results["<module>"]
    expected = {TaintFact("sys.argv", 1)}

    assert module.facts_for("a") == expected
    assert module.facts_for("x") == expected


def test_for_iteration_taints_accumulator():
    results = run_taint(
        "total = ''\n"
        "for line in sys.stdin:\n"
        "    total = total + line\n"
    )

    module = results["<module>"]
    expected = {TaintFact("sys.stdin", 2)}

    assert module.facts_for("line") == expected
    assert module.facts_for("total") == expected


def test_with_target_propagates():
    results = run_taint(
        "with open(os.environ['HOME']) as handle:\n"
        "    data = handle\n"
    )

    module = results["<module>"]
    expected = {TaintFact("os.environ", 1)}

    assert module.facts_for("handle") == expected
    assert module.facts_for("data") == expected


def test_branch_merge_preserves_then_branch_taint():
    results = run_taint(
        "x = 'safe'\n"
        "if flag:\n"
        "    x = input()\n"
        "y = x\n"
    )

    assert results["<module>"].facts_for("y") == {TaintFact("input", 3)}


def test_branch_merge_preserves_else_branch_taint():
    results = run_taint(
        "u = input()\n"
        "x = u\n"
        "if flag:\n"
        "    x = 'safe'\n"
        "y = x\n"
    )

    assert results["<module>"].facts_for("y") == {TaintFact("input", 1)}


def test_loop_carried_taint_reaches_fixpoint():
    results = run_taint(
        "u = input()\n"
        "if flag:\n"
        "    x = ''\n"
        "else:\n"
        "    x = 0\n"
        "for _ in range(3):\n"
        "    y = x\n"
        "    x = u\n"
        "z = y\n"
    )

    module = results["<module>"]
    expected = {TaintFact("input", 1)}

    assert module.facts_for("y") == expected
    assert module.facts_for("z") == expected


def test_del_kills_taint_without_touching_copies():
    results = run_taint(
        "x = input()\n"
        "y = x\n"
        "del x\n"
        "z = x\n"
    )

    module = results["<module>"]

    assert module.facts_for("y") == {TaintFact("input", 1)}
    assert module.facts_for("x") == frozenset()
    assert module.facts_for("z") == frozenset()


def test_shlex_sanitizers_exempt_only_shell_sinks():
    results = run_taint(
        "u = input()\n"
        "q = shlex.quote(u)\n"
        "j = shlex.join([u])\n"
    )

    module = results["<module>"]

    for name in ("q", "j"):
        facts = module.facts_for(name)
        assert len(facts) == 1, name

        fact = next(iter(facts))
        assert fact.source_id == "input", name
        assert fact.exempt_sinks == frozenset({SINK_SHELL_COMMAND}), name
        assert fact.is_dangerous_for(SINK_CODE_EXECUTION) is True, name
        assert fact.is_dangerous_for(SINK_DESERIALIZATION) is True, name

    u_facts = module.facts_for("u")
    assert len(u_facts) == 1
    assert next(iter(u_facts)).is_dangerous_for(SINK_SHELL_COMMAND) is True


def test_nested_sanitizer_call_is_not_recognized():
    results = run_taint(
        "u = input()\n"
        "n = 'echo ' + shlex.quote(u)\n"
    )

    facts = results["<module>"].facts_for("n")

    assert len(facts) == 1
    assert next(iter(facts)).is_dangerous_for(SINK_SHELL_COMMAND) is True


def test_source_variable_keeps_taint_after_sanitizing_copy():
    results = run_taint(
        "u = input()\n"
        "q = shlex.quote(u)\n"
    )

    u_facts = results["<module>"].facts_for("u")

    assert len(u_facts) == 1
    assert next(iter(u_facts)).exempt_sinks == frozenset()


def test_functions_are_isolated():
    results = run_taint(
        "def f():\n"
        "    x = input()\n"
        "    return x\n"
        "\n"
        "def g():\n"
        "    y = f()\n"
        "    return y\n"
    )

    assert results["f"].facts_for("x") == {TaintFact("input", 2)}
    assert results["g"].facts_for("y") == frozenset()


def test_closure_read_does_not_leak_taint():
    results = run_taint(
        "x = input()\n"
        "\n"
        "def inner():\n"
        "    return x\n"
    )

    assert results["<module>"].facts_for("x") == {TaintFact("input", 1)}
    assert results["inner"].facts_for("x") == frozenset()


def test_parameters_start_untainted():
    results = run_taint(
        "def f(data):\n"
        "    result = data\n"
        "    return result\n"
    )

    assert results["f"].facts_for("result") == frozenset()


def test_multiple_sources_union_in_expression():
    results = run_taint(
        "a = input()\n"
        "b = sys.argv\n"
        "c = a + b\n"
    )

    facts = results["<module>"].facts_for("c")

    assert len(facts) == 2
    assert {fact.source_id for fact in facts} == {"input", "sys.argv"}


def test_repeated_analysis_is_deterministic():
    code = (
        "u = input()\n"
        "if flag:\n"
        "    x = u\n"
        "else:\n"
        "    x = 'safe'\n"
        "del u\n"
        "for i in range(2):\n"
        "    y = x\n"
    )

    assert run_taint(code) == run_taint(code)


def test_import_bindings_start_clean():
    results = run_taint(
        "import os.path\n"
        "from json import loads\n"
        "x = os.path\n"
        "y = loads\n"
    )

    module = results["<module>"]

    assert module.facts_for("x") == frozenset()
    assert module.facts_for("y") == frozenset()


def test_match_subject_binds_pattern_names():
    results = run_taint(
        "match sys.argv:\n"
        "    case str(text):\n"
        "        x = text\n"
    )

    module = results["<module>"]
    expected = {TaintFact("sys.argv", 1)}

    assert module.facts_for("text") == expected
    assert module.facts_for("x") == expected
