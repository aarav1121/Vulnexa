
from vulnexa.rules.engine import RuleEngine, RuleVisitor
from vulnexa.rules.registry import RuleRegistry


class RecordingRule:
    """
    Minimal rule-like object that matches every Call node.
    Not a SecurityRule subclass; only duck-types the engine contract.
    """

    rule_id = "TEST-CALL"
    title = "Call"
    severity = "INFO"
    message = "call found"
    recommendation = "none"

    def matches(self, node):
        import ast
        return isinstance(node, ast.Call)

    def create_finding(self, node, file_path, function):
        from vulnexa.models.finding import Finding
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            file_path=file_path,
            line_number=node.lineno,
            message=self.message,
            recommendation=self.recommendation,
            function=function,
        )


def build_engine():
    registry = RuleRegistry()
    registry.register(RecordingRule())
    return RuleEngine(registry)


def test_engine_detects_call_in_function_context():
    engine = build_engine()

    findings = engine.analyze(
        __import__("ast").parse("helper()\n"),
        file_path="t.py",
    )

    assert len(findings) == 1
    assert findings[0].function == "<module>"
    assert findings[0].line_number == 1


def test_engine_reports_method_with_class_context():
    import ast

    code = (
        "class Service:\n"
        "    def run(self):\n"
        "        helper()\n"
    )

    findings = build_engine().analyze(ast.parse(code), file_path="t.py")

    assert len(findings) == 1
    assert findings[0].function == "Service.run"


def test_engine_scans_nested_functions():
    import ast

    code = (
        "def outer():\n"
        "    def inner():\n"
        "        helper()\n"
    )

    findings = build_engine().analyze(ast.parse(code), file_path="t.py")

    assert len(findings) == 1
    assert findings[0].function == "outer.inner"


def test_visitor_independent_per_analyze_call():
    import ast

    engine = build_engine()
    tree = ast.parse("helper()\n")

    first = engine.analyze(tree, file_path="t.py")
    second = engine.analyze(tree, file_path="t.py")

    assert len(first) == len(second) == 1
