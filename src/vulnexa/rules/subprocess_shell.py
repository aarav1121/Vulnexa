
import ast

from vulnexa.rules.base import SecurityRule


class SubprocessShellRule(SecurityRule):
    """
    Detect subprocess calls made with shell=True.

    Using shell=True passes the command through the system shell,
    which enables command injection when parts of the command
    come from untrusted input.
    """

    SUBPROCESS_FUNCTIONS = {
        "run",
        "call",
        "check_call",
        "check_output",
        "Popen",
    }

    def __init__(self):
        super().__init__(
            rule_id="VULN-005",
            title="subprocess call with shell=True",
            severity="HIGH",
            message=(
                "Calling subprocess with shell=True exposes "
                "the command to shell injection."
            ),
            recommendation=(
                "Use shell=False (the default) and pass the "
                "command as a list of arguments."
            )
        )

    def _is_subprocess_call(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute):
            return (
                node.func.attr in self.SUBPROCESS_FUNCTIONS
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "subprocess"
            )

        if isinstance(node.func, ast.Name):
            return node.func.id in self.SUBPROCESS_FUNCTIONS

        return False

    def _has_shell_true(self, node: ast.Call) -> bool:
        return any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        )

    def matches(self, node: ast.AST) -> bool:
        """
        Check for subprocess.*(...) calls that pass shell=True.
        """

        return (
            isinstance(node, ast.Call)
            and self._is_subprocess_call(node)
            and self._has_shell_true(node)
        )
