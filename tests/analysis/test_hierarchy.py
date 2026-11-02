
import ast

from vulnexa.analysis.hierarchy import analyze_relationships


def parse_result(code: str):
    return analyze_relationships(ast.parse(code))


def test_class_bases_are_recorded():
    code = (
        "class Base:\n"
        "    pass\n"
        "\n"
        "class Child(Base):\n"
        "    pass\n"
    )

    result = parse_result(code)

    child = result.classes["Child"]
    assert child.bases == ["Base"]


def test_dotted_base_names_are_rendered():
    code = "class Child(abstract.Base):\n    pass\n"

    result = parse_result(code)

    assert result.classes["Child"].bases == ["abstract.Base"]


def test_methods_are_listed_on_the_class():
    code = (
        "class Service:\n"
        "    def start(self):\n"
        "        pass\n"
        "\n"
        "    def stop(self):\n"
        "        pass\n"
    )

    result = parse_result(code)

    assert result.classes["Service"].methods == ["start", "stop"]


def test_subclasses_can_be_found():
    code = (
        "class Base:\n"
        "    pass\n"
        "\n"
        "class Child(Base):\n"
        "    pass\n"
    )

    result = parse_result(code)
    subclasses = result.get_subclasses("Base")

    assert [info.name for info in subclasses] == ["Child"]


def test_call_graph_records_function_calls():
    code = (
        "def helper():\n"
        "    pass\n"
        "\n"
        "def main():\n"
        "    helper()\n"
    )

    result = parse_result(code)

    assert "helper" in result.functions["main"].calls
    assert result.get_callers("helper") == {"main"}


def test_method_calls_recorded_with_self_prefix():
    code = (
        "class Service:\n"
        "    def start(self):\n"
        "        pass\n"
        "\n"
        "    def run(self):\n"
        "        self.start()\n"
    )

    result = parse_result(code)

    assert "self.start" in result.functions["Service.run"].calls


def test_module_level_calls_are_tracked():
    code = "print('hello')\n"

    result = parse_result(code)

    assert "print" in result.functions["<module>"].calls
