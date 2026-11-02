
import ast

from vulnexa.rules.base import SecurityRule


class UnsafeDeserializationRule(SecurityRule):
    """
    Detect unsafe pickle deserialization calls.

    Flags pickle.load() and pickle.loads(). Deserializing data
    from untrusted sources can execute arbitrary code.
    """

    DESERIALIZATION_FUNCTIONS = {"load", "loads"}

    def __init__(self):
        super().__init__(
            rule_id="VULN-003",
            title="Unsafe deserialization with pickle",
            severity="HIGH",
            message=(
                "pickle.load()/loads() can execute "
                "arbitrary code during deserialization."
            ),
            recommendation=(
                "Never deserialize data from an untrusted "
                "source with pickle. Use a safe format "
                "such as JSON instead."
            )
        )

    def matches(self, node: ast.AST) -> bool:
        """
        Check for pickle.load(...) or pickle.loads(...) calls.
        """

        if not isinstance(node, ast.Call):
            return False

        if not isinstance(node.func, ast.Attribute):
            return False

        if node.func.attr not in self.DESERIALIZATION_FUNCTIONS:
            return False

        return (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pickle"
        )
