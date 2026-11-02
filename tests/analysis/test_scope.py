
import ast

from vulnexa.analysis.scope import analyze_scopes


def parse_result(code: str):
    return analyze_scopes(ast.parse(code))


def test_scopes_are_created_for_functions_and_classes():
    code = (
        "def run():\n"
        "    pass\n"
        "\n"
        "class Service:\n"
        "    def method(self):\n"
        "        pass\n"
    )

    result = parse_result(code)
    quals = [scope.qualname for scope in result.scopes]

    assert "<module>" in quals
    assert "run" in quals
    assert "Service" in quals
    assert "Service.method" in quals


def test_definitions_and_references_are_tracked():
    code = "def run():\n    total = 1\n    print(total)\n"

    result = parse_result(code)
    run_scope = result.find_scope("run")

    assert "total" in run_scope.definitions
    assert "total" in run_scope.references


def test_undefined_reference_detected():
    code = "def run():\n    print(missing_name)\n"

    result = parse_result(code)

    assert len(result.undefined_references) == 1
    issue = result.undefined_references[0]
    assert issue.name == "missing_name"
    assert issue.scope_qualname == "run"
    assert issue.line_number == 2


def test_builtins_do_not_produce_undefined_warnings():
    code = "def run():\n    print(len([1]))\n"

    result = parse_result(code)

    assert result.undefined_references == []


def test_module_globals_visible_in_functions():
    code = "limit = 10\n\ndef run():\n    return limit\n"

    result = parse_result(code)

    assert result.undefined_references == []


def test_class_scope_not_visible_inside_methods():
    code = (
        "class Service:\n"
        "    setting = 1\n"
        "\n"
        "    def run(self):\n"
        "        return setting\n"
    )

    result = parse_result(code)

    names = [issue.name for issue in result.undefined_references]
    assert "setting" in names


def test_global_declaration_resolves_to_module():
    code = (
        "counter = 0\n"
        "\n"
        "def bump():\n"
        "    global counter\n"
        "    counter = counter + 1\n"
    )

    result = parse_result(code)

    assert result.undefined_references == []


def test_unused_local_variable_detected():
    code = "def run():\n    unused = 42\n    return 1\n"

    result = parse_result(code)

    assert len(result.unused_variables) == 1
    issue = result.unused_variables[0]
    assert issue.name == "unused"
    assert issue.scope_qualname == "run"


def test_underscore_names_not_reported_unused():
    code = "def run():\n    _ = compute()\n    return 1\n"

    result = parse_result(code)

    assert result.unused_variables == []


def test_variable_used_in_nested_scope_is_not_unused():
    code = (
        "def outer():\n"
        "    value = 5\n"
        "    def inner():\n"
        "        return value\n"
        "    return inner\n"
    )

    result = parse_result(code)

    unused_names = [issue.name for issue in result.unused_variables]
    assert "value" not in unused_names


def test_method_definitions_not_reported_unused():
    code = (
        "class Service:\n"
        "    def run(self):\n"
        "        return 1\n"
    )

    result = parse_result(code)

    assert result.unused_variables == []
