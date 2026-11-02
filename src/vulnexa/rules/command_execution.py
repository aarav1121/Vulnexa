
import ast

from vulnexa.rules.base import SecurityRule


class SystemCommandRule(SecurityRule):
    """
    Detect direct calls to os.system().

    Running operating-system commands with strings built from
    untrusted input enables command injection.
    """

    def __init__(self):
        super().__init__(
            rule_id="VULN-004",
            title="OS command execution with os.system()",
            severity="HIGH",
            message=(
                "os.system() executes operating-system "
                "commands through the shell."
            ),
            recommendation=(
                "Avoid os.system() with untrusted input. "
                "Prefer the subprocess module with a list "
                "of arguments and shell=False."
            )
        )

    def matches(self, node: ast.AST) -> bool:
        """
        Check for os.system(...) calls.
        """

        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "system"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
        )
