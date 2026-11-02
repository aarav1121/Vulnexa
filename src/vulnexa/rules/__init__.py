
"""
Security rule package for Vulnexa.

Exposes the default rule set and a factory that builds a
fully populated RuleRegistry for the scanner.
"""

from vulnexa.rules.base import SecurityRule
from vulnexa.rules.engine import RuleEngine
from vulnexa.rules.insecure_functions import EvalRule, ExecRule
from vulnexa.rules.registry import RuleRegistry
from vulnexa.rules.serialization import UnsafeDeserializationRule
from vulnexa.rules.command_execution import SystemCommandRule
from vulnexa.rules.subprocess_shell import SubprocessShellRule


DEFAULT_RULES = [
    EvalRule,
    ExecRule,
    UnsafeDeserializationRule,
    SystemCommandRule,
    SubprocessShellRule,
]


def create_default_registry() -> RuleRegistry:
    """
    Build a RuleRegistry preloaded with every built-in Vulnexa rule.
    """

    registry = RuleRegistry()

    for rule_class in DEFAULT_RULES:
        registry.register(rule_class())

    return registry


__all__ = [
    "SecurityRule",
    "RuleEngine",
    "RuleRegistry",
    "DEFAULT_RULES",
    "create_default_registry",
]
