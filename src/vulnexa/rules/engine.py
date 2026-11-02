import ast

from vulnexa.rules.registry import RuleRegistry
from vulnexa.models.finding import Finding


class RuleVisitor(ast.NodeVisitor):
    """
    Traverses the AST and executes all registered security rules.
    """

    def __init__(self, registry: RuleRegistry, file_path: str):
        self.registry = registry
        self.file_path = file_path
        self.findings: list[Finding] = []
        self.scope_stack: list[tuple[str, str]] = []

    def _current_function(self) -> str:
        """
        Build the qualified function/method context, e.g.
        "MyClass.method" or "<module>" at the top level.
        """

        if not self.scope_stack:
            return "<module>"

        return ".".join(name for name, _ in self.scope_stack)

    def visit(self, node):
        """
        Check the current AST node against all registered rules.
        """

        current_function = self._current_function()

        for rule in self.registry.get_rules():

            if rule.matches(node):

                finding = rule.create_finding(
                    node=node,
                    file_path=self.file_path,
                    function=current_function
                )

                self.findings.append(finding)

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.scope_stack.append((node.name, "function"))

            self.generic_visit(node)

            self.scope_stack.pop()

        elif isinstance(node, ast.ClassDef):
            self.scope_stack.append((node.name, "class"))

            self.generic_visit(node)

            self.scope_stack.pop()

        else:
            self.generic_visit(node)


class RuleEngine:
    """
    Coordinates security rule execution and AST analysis.
    """

    def __init__(self, registry: RuleRegistry):
        self.registry = registry

    def analyze(self, syntax_tree: ast.AST, file_path: str):
        """
        Analyze an AST tree and return all detected findings.
        """

        visitor = RuleVisitor(
            registry=self.registry,
            file_path=file_path
        )

        visitor.visit(syntax_tree)

        return visitor.findings
