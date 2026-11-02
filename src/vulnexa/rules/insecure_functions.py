
import ast

from vulnexa.rules.base import SecurityRule


class EvalRule(SecurityRule):
    """
    Detect direct calls to eval().
    """

    def __init__(self):
        super().__init__(
            rule_id="VULN-001",
            title="Use of eval()",
            severity="WARNING",
            message=(
                "eval() can execute dynamically "
                "supplied Python expressions."
            ),
            recommendation=(
                "Avoid using eval() with untrusted "
                "input. Use safer alternatives."
            )
        )

    def matches(self, node: ast.AST) -> bool:
        """
        Check whether the AST node represents a direct eval() call.
        """

        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "eval"
        )


class ExecRule(SecurityRule):
    """
    Detect direct calls to exec().
    """

    def __init__(self):
        super().__init__(
            rule_id="VULN-002",
            title="Use of exec()",
            severity="WARNING",
            message=(
                "exec() can execute dynamically "
                "supplied Python statements."
            ),
            recommendation=(
                "Avoid using exec() with untrusted "
                "input. Use safer alternatives."
            )
        )

    def matches(self, node: ast.AST) -> bool:
        """
        Check whether the AST node represents a direct exec() call.
        """

        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "exec"
        )
