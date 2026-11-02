
import ast
import os
import sys

import pytest

# Make the src/ layout importable when running pytest
# without requiring a manually configured PYTHONPATH.
SRC_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "src")
)
sys.path.insert(0, SRC_PATH)

from vulnexa.models.finding import Finding
from vulnexa.rules import create_default_registry
from vulnexa.rules.engine import RuleEngine
from vulnexa.rules.registry import RuleRegistry


@pytest.fixture
def make_finding():
    """
    Build a Finding with sensible defaults for testing.
    """

    def _make_finding(**overrides):
        defaults = dict(
            rule_id="VULN-001",
            title="Use of eval()",
            severity="WARNING",
            file_path="test.py",
            line_number=1,
            message="message",
            recommendation="recommendation",
            function="eval",
        )

        defaults.update(overrides)
        return Finding(**defaults)

    return _make_finding


@pytest.fixture
def registry():
    """
    A registry preloaded with all built-in Vulnexa rules.
    """

    return create_default_registry()


@pytest.fixture
def engine(registry):
    """
    A RuleEngine using the default rule set.
    """

    return RuleEngine(registry)


@pytest.fixture
def run_rule():
    """
    Run a single security rule against source code and
    return the resulting findings.

    Used for rule-level positive and negative test cases.
    """

    def _run_rule(rule, code: str):
        syntax_tree = ast.parse(code)
        single_rule_registry = RuleRegistry()
        single_rule_registry.register(rule)

        engine = RuleEngine(single_rule_registry)
        return engine.analyze(syntax_tree, file_path="<test>")

    return _run_rule


@pytest.fixture
def scan_code(engine):
    """
    Parse source code with the default rule set and
    return the resulting findings.
    """

    def _scan_code(code: str):
        syntax_tree = ast.parse(code)
        return engine.analyze(syntax_tree, file_path="<test>")

    return _scan_code
