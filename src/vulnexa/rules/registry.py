from vulnexa.rules.base import SecurityRule


class RuleRegistry:
    """
    Manages all registered security rules in Vulnexa.
    """

    def __init__(self):
        self._rules = {}

    def register(self, rule: SecurityRule):
        """
        Register a security rule using its unique rule ID.
        """

        if rule.rule_id in self._rules:
            raise ValueError(
                f"Rule already registered: {rule.rule_id}"
            )

        self._rules[rule.rule_id] = rule

    def get_rules(self):
        """
        Return all registered security rules.
        """

        return list(self._rules.values())

    def get_rule(self, rule_id: str):
        """
        Return a specific rule using its ID.
        """

        return self._rules.get(rule_id)

    def unregister(self, rule_id: str):
        """
        Remove a rule from the registry.

        Raises KeyError when the rule ID is not registered.
        """

        if rule_id not in self._rules:
            raise KeyError(
                f"Rule not registered: {rule_id}"
            )

        del self._rules[rule_id]

    @property
    def rule_ids(self) -> list[str]:
        """
        Return the IDs of all registered rules.
        """

        return list(self._rules.keys())

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, rule_id: str) -> bool:
        return rule_id in self._rules