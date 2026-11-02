
import ast

from vulnexa.analysis.symbols import (
    SYMBOL_CLASS,
    SYMBOL_FUNCTION,
    SYMBOL_IMPORT,
    SYMBOL_METHOD,
    SYMBOL_PARAMETER,
    SYMBOL_VARIABLE,
    collect_symbols,
)


def parse(code: str):
    return ast.parse(code)


def symbol_pairs(table):
    return [
        (symbol.name, symbol.kind, symbol.scope_path)
        for symbol in table.flatten()
    ]


def test_module_variables_and_functions():
    table = collect_symbols(parse("x = 1\ndef run():\n    y = 2\n"))

    pairs = symbol_pairs(table)

    assert ("x", SYMBOL_VARIABLE, "") in pairs
    assert ("run", SYMBOL_FUNCTION, "") in pairs
    assert ("y", SYMBOL_VARIABLE, "run") in pairs


def test_methods_are_recorded_inside_classes():
    code = (
        "class Service:\n"
        "    def run(self):\n"
        "        pass\n"
    )

    table = collect_symbols(parse(code))
    pairs = symbol_pairs(table)

    assert ("Service", SYMBOL_CLASS, "") in pairs
    assert ("run", SYMBOL_METHOD, "Service") in pairs
    assert ("self", SYMBOL_PARAMETER, "Service.run") in pairs


def test_imports_use_bound_names():
    code = (
        "import os\n"
        "import os.path\n"
        "from json import loads as json_loads\n"
    )

    table = collect_symbols(parse(code))
    pairs = symbol_pairs(table)

    assert ("os", SYMBOL_IMPORT, "") in pairs
    assert ("os.path", SYMBOL_IMPORT, "") not in pairs
    assert ("json_loads", SYMBOL_IMPORT, "") in pairs


def test_find_scope_returns_nested_table():
    code = (
        "class Service:\n"
        "    def run(self):\n"
        "        pass\n"
    )

    table = collect_symbols(parse(code))
    scope = table.find_scope("Service.run")

    assert scope is not None
    assert scope.kind == "function"
    assert "self" in scope.symbols


def test_walk_visits_all_tables():
    code = (
        "def outer():\n"
        "    def inner():\n"
        "        pass\n"
    )

    table = collect_symbols(parse(code))
    names = [t.name for t in table.walk()]

    assert "<module>" in names
    assert "outer" in names
    assert "inner" in names
