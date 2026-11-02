
from abc import ABC, abstractmethod
import ast

from vulnexa.models.finding import Finding


class SecurityRule(ABC):
    """
    Base interface for all Vulnexa security detection rules.

    Every security rule must provide its metadata and implement
    the matches() method.
    """

    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,
        message: str,
        recommendation: str
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.message = message
        self.recommendation = recommendation

    @abstractmethod
    def matches(self, node: ast.AST) -> bool:
        """
        Determine whether an AST node matches this security rule.

        Each individual rule implements its own detection logic.
        """
        pass

    def create_finding(
        self,
        node: ast.AST,
        file_path: str,
        function: str
    ) -> Finding:
        """
        Create a standardized Finding from the rule metadata.
        """

        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            file_path=file_path,
            line_number=getattr(node, "lineno", 0),
            message=self.message,
            recommendation=self.recommendation,
            function=function
        )
