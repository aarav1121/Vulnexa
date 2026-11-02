
"""
Taint data models for Vulnexa.

Defines the shared vocabulary for taint analysis:

- TaintFact: one taint origin attached to a variable.
- TaintSource / TaintSink / TaintSanitizer: declarative
  matchers used by the taint registry and the propagation
  engine.
- TaintFinding / TaintAnalysisResult: structured output.

Taint-fact identity and union semantics (stable contract):

- A TaintFact is a frozen value; two facts are equal only when
  source_id, source_line, and exempt_sinks all match.
- The taint state of one variable is a set of facts. Union of
  two states is plain set union.
- A fact is dangerous for a sink kind unless that kind appears
  in exempt_sinks. A variable is dangerous for a sink kind when
  any of its facts is dangerous for that kind.
- Propagation copies facts unchanged, so the same origin keeps
  the same identity at every program point and the fixpoint
  converges when fact sets stop growing.
- Sanitizers never delete facts. They can only introduce a
  companion fact with a larger exempt_sinks set. Because
  exemptions are part of the identity, a value sanitized on one
  path and unsanitized on another keeps both facts, and the
  unsanitized fact still reports the flow.

This module only reads the AST; scanned source code is never
executed.
"""

import ast
from dataclasses import asdict, dataclass, field


# Sink kinds: what an attacker can influence at the sink.
SINK_CODE_EXECUTION = "code-execution"
SINK_SHELL_COMMAND = "shell-command"
SINK_DESERIALIZATION = "deserialization"

# Optional sink conditions.
CONDITION_SHELL_TRUE = "shell-true"


def static_dotted_name(node):
    """
    Render a name/attribute chain as a dotted string.

    Returns None when the chain is not statically resolvable
    (calls, subscripts, literals), keeping matching precise.
    """

    parts = []
    current = node

    while current is not None:
        if isinstance(current, ast.Name):
            parts.append(current.id)
            current = None
        elif isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        else:
            return None

    return ".".join(reversed(parts))


def _resolve_dotted(dotted, import_map):
    """
    Replace a leading imported binding in a dotted path.

    Returns None when the first segment is not a recorded
    import, so unknown names are never guessed.
    """

    if not import_map:
        return None

    parts = dotted.split(".")
    target = import_map.get(parts[0])

    if target is None:
        return None

    return ".".join([target] + parts[1:])


def _call_target_matches(node, call_names, attribute_paths, import_map=None):
    """
    Check whether a Call node targets one of the given bare
    names or dotted attribute paths.

    Raw dotted paths match first; import resolution only adds
    matches for explicitly recorded import bindings.
    """

    if not isinstance(node, ast.Call):
        return False

    if call_names and isinstance(node.func, ast.Name):
        if node.func.id in call_names:
            return True

    if attribute_paths:
        dotted = static_dotted_name(node.func)
        if dotted is not None:
            if dotted in attribute_paths:
                return True
            resolved = _resolve_dotted(dotted, import_map)
            if resolved is not None and resolved in attribute_paths:
                return True

    return False


def _attribute_target_matches(node, attribute_paths, import_map=None):
    """
    Check whether an Attribute node has one of the given dotted
    paths.

    Raw dotted paths match first; import resolution only adds
    matches for explicitly recorded import bindings.
    """

    if not isinstance(node, ast.Attribute):
        return False

    dotted = static_dotted_name(node)
    if dotted is None:
        return False

    if dotted in attribute_paths:
        return True

    resolved = _resolve_dotted(dotted, import_map)

    return resolved is not None and resolved in attribute_paths


def _condition_shell_true(node):
    """
    Check for a literal shell=True keyword on a call.
    """

    for keyword in node.keywords:
        if keyword.arg == "shell":
            value = keyword.value
            if isinstance(value, ast.Constant) and value.value is True:
                return True

    return False


_CONDITION_CHECKS = {
    CONDITION_SHELL_TRUE: _condition_shell_true,
}


@dataclass(frozen=True)
class TaintFact:
    """
    One taint origin attached to a variable.

    Frozen and hashable: facts are stored in sets and union is
    plain set union. See the module docstring for the full
    identity and union contract.
    """

    source_id: str
    source_line: int
    exempt_sinks: frozenset = frozenset()

    def is_exempt_for(self, sink_kind: str) -> bool:
        return sink_kind in self.exempt_sinks

    def is_dangerous_for(self, sink_kind: str) -> bool:
        return not self.is_exempt_for(sink_kind)

    def with_cleared_sinks(self, sink_kinds) -> "TaintFact":
        """
        Return a copy whose exempt set is extended by sink_kinds.

        The original fact is never modified.
        """

        return TaintFact(
            source_id=self.source_id,
            source_line=self.source_line,
            exempt_sinks=self.exempt_sinks | frozenset(sink_kinds),
        )


@dataclass(frozen=True)
class TaintSource:
    """
    A declarative untrusted-input source.

    match_call_names: bare function names matched on Call nodes
      (for example "input").
    match_attribute_paths: dotted attribute chains matched on
      Attribute nodes (for example "sys.argv"). The chain must
      be statically resolvable, so "flask.request.args" never
      matches the "request.args" source and "self.request.args"
      never matches either.
    """

    source_id: str
    kind: str
    match_call_names: tuple = ()
    match_attribute_paths: tuple = ()

    def matches(self, node, import_map=None) -> bool:
        if isinstance(node, ast.Call):
            return _call_target_matches(
                node,
                self.match_call_names,
                self.match_attribute_paths,
                import_map,
            )

        if isinstance(node, ast.Attribute):
            return _attribute_target_matches(
                node,
                self.match_attribute_paths,
                import_map,
            )

        return False


@dataclass
class TaintFinding:
    """
    Structured source-to-sink taint finding.
    """

    rule_id: str
    title: str
    severity: str
    file_path: str
    function: str
    sink_label: str
    sink_line: int
    source_id: str
    source_line: int
    message: str
    recommendation: str

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class TaintSink:
    """
    A declarative security-sensitive call.

    Sinks match Call nodes only. An optional condition narrows
    the match (for example CONDITION_SHELL_TRUE requires a
    literal shell=True keyword on the call). Unknown conditions
    never match so that malformed declarations fail closed.
    """

    rule_id: str
    sink_kind: str
    title: str
    severity: str
    message: str
    recommendation: str
    match_call_names: tuple = ()
    match_attribute_paths: tuple = ()
    condition: str = None

    def matches(self, node, import_map=None) -> bool:
        if not _call_target_matches(
            node,
            self.match_call_names,
            self.match_attribute_paths,
            import_map,
        ):
            return False

        if self.condition is None:
            return True

        check = _CONDITION_CHECKS.get(self.condition)

        if check is None:
            return False

        return check(node)

    def create_finding(self, node, file_path, function, fact) -> TaintFinding:
        """
        Build a structured TaintFinding for a matched sink call.

        Mirrors SecurityRule.create_finding: the node supplies
        the location and call spelling, the fact supplies the
        origin.
        """

        sink_label = static_dotted_name(node.func)
        if sink_label is None:
            sink_label = getattr(node.func, "id", "<unknown>")

        return TaintFinding(
            rule_id=self.rule_id,
            title=self.title,
            severity=self.severity,
            file_path=file_path,
            function=function,
            sink_label=sink_label,
            sink_line=getattr(node, "lineno", 0),
            source_id=fact.source_id,
            source_line=fact.source_line,
            message=self.message,
            recommendation=self.recommendation,
        )


@dataclass(frozen=True)
class TaintSanitizer:
    """
    A declarative sanitizer.

    Sanitizers are sink-specific: clears_sinks lists the sink
    kinds the sanitizer makes safe. Sanitizers are never
    universal; taint is preserved for every sink kind not
    listed. When safety cannot be established for a sink kind,
    that kind must not appear in clears_sinks.
    """

    sanitizer_id: str
    clears_sinks: frozenset
    match_call_names: tuple = ()
    match_attribute_paths: tuple = ()

    def matches(self, node, import_map=None) -> bool:
        return _call_target_matches(
            node,
            self.match_call_names,
            self.match_attribute_paths,
            import_map,
        )


@dataclass
class TaintAnalysisResult:
    """
    Taint analysis output for one source file.
    """

    file_path: str
    findings: list = field(default_factory=list)

    def to_dict(self):
        return {
            "file_path": self.file_path,
            "findings": [
                finding.to_dict() for finding in self.findings
            ],
        }
