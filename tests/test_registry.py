
import pytest

from vulnexa.rules.base import SecurityRule
from vulnexa.rules.registry import RuleRegistry


class DummyRule(SecurityRule):

    def __init__(self, rule_id="TEST-001"):
        super().__init__(
            rule_id=rule_id,
            title="Dummy",
            severity="LOW",
            message="message",
            recommendation="recommendation"
        )

    def matches(self, node) -> bool:
        return False


def test_register_and_get_rule():
    registry = RuleRegistry()
    rule = DummyRule()

    registry.register(rule)

    assert registry.get_rule("TEST-001") is rule
    assert registry.get_rules() == [rule]


def test_register_duplicate_rule_id_raises():
    registry = RuleRegistry()
    registry.register(DummyRule())

    with pytest.raises(ValueError):
        registry.register(DummyRule())


def test_get_missing_rule_returns_none():
    registry = RuleRegistry()

    assert registry.get_rule("MISSING") is None


def test_rule_ids_len_and_contains():
    registry = RuleRegistry()
    registry.register(DummyRule("TEST-001"))
    registry.register(DummyRule("TEST-002"))

    assert registry.rule_ids == ["TEST-001", "TEST-002"]
    assert len(registry) == 2
    assert "TEST-001" in registry
    assert "TEST-003" not in registry
