
"""
Taint propagation engine for Vulnexa.

Performs an intraprocedural, flow-sensitive may-analysis over
the control flow graph of the module body and every function:

- Taint enters through the sources registered in
  analysis/taint_registry.py.
- Facts propagate through assignments, augmented and walrus
  assignments, binary operations, f-strings and formatting,
  subscripts, attributes, and unknown calls with tainted
  arguments.
- An assignment evaluates the full right-hand side first and
  then replaces the target's previous facts; other variables
  keep their facts.
- Branch merges union incoming fact sets; loops reach a
  fixpoint. Facts only grow and the fact universe is finite,
  so the iteration terminates.
- Loop back edges re-enter at the loop statement, not at the
  start of the header block: statements before the loop run
  once, and facts carried by the body flow back into the loop
  until the state is stable.
- `del` removes a variable's facts without creating new ones,
  matching the Phase 6 kill semantics.
- Sanitizers add sink-specific exemptions to the facts of the
  sanitized value; provenance is never deleted. Only a direct
  sanitizer call as the whole right-hand side is recognized.
- Each function (and the module body) is analyzed in complete
  isolation: parameters start untainted and no facts cross
  scope boundaries.
- After the fixpoint, registered sinks are matched on call
  nodes with the state in effect at each statement; one
  finding per distinct dangerous source origin is emitted.
  Import aliases resolve only through explicit import
  statements and are never guessed.

Approximations (documented):

- Nested function, lambda, and class-body expressions are not
  analyzed (matching the dataflow module's scope skipping).
- Unknown calls propagate argument taint; no call summaries.
- Sanitizer recognition only on a direct right-hand-side call;
  sanitizers nested inside larger expressions propagate
  without exemptions.
- Reads of global/nonlocal names, closure variables, and
  parameters start untainted (no interprocedural propagation).
- Class body statements belong to no CFG block (inherited
  limitation of the CFG builder).
- Walrus evaluation order inside one expression is
  approximated: targets are bound before final fact collection.

This module only reads the AST; scanned source code is never
executed.
"""

import ast
from dataclasses import dataclass, field

from vulnexa.analysis.cfg import build_cfgs
from vulnexa.analysis.dataflow import SKIP_SUBTREE_NODES
from vulnexa.analysis.taint_models import TaintFact
from vulnexa.analysis.taint_registry import (
    match_sanitizer,
    match_sinks,
    match_source,
)


@dataclass
class FunctionTaintResult:
    """
    Taint facts and findings for one function or the module
    body.
    """

    function_name: str
    tainted_variables: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    def facts_for(self, name: str) -> frozenset:
        """
        Return the facts recorded for one variable name.
        """

        return self.tainted_variables.get(name, frozenset())


def _walk_scope_local(node):
    """
    Walk an expression without descending into nested scopes.
    """

    stack = [node]

    while stack:
        current = stack.pop()
        yield current

        for child in ast.iter_child_nodes(current):
            if isinstance(child, SKIP_SUBTREE_NODES):
                continue
            stack.append(child)


def _iter_own_expressions(stmt):
    """
    Yield the expression nodes a statement evaluates itself.

    Statements that own nested statement lists (if/while/for/
    with/try/match) are analyzed as separate blocks, so only
    their header expressions belong to this statement.
    """

    if isinstance(stmt, ast.If):
        yield stmt.test

    elif isinstance(stmt, ast.While):
        yield stmt.test

    elif isinstance(stmt, (ast.For, ast.AsyncFor)):
        yield stmt.iter
        yield stmt.target

    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            yield item.context_expr
            if item.optional_vars is not None:
                yield item.optional_vars

    elif isinstance(stmt, ast.Match):
        yield stmt.subject
        for case in stmt.cases:
            yield case.pattern

    elif isinstance(stmt, (ast.Try, ast.TryStar)):
        return

    elif isinstance(stmt, ast.ExceptHandler):
        if stmt.type is not None:
            yield stmt.type

    else:
        yield stmt


def _subtree_facts(node, state, import_map) -> set:
    """
    Facts produced by a subtree: direct source occurrences
    plus the facts of tainted names read in it.
    """

    facts = set()

    for current in _walk_scope_local(node):

        source = match_source(current, import_map)
        if source is not None:
            facts.add(
                TaintFact(
                    source_id=source.source_id,
                    source_line=getattr(current, "lineno", 0),
                )
            )

        elif isinstance(current, ast.Name) and isinstance(current.ctx, ast.Load):
            facts |= state.get(current.id, frozenset())

    return facts


def _eval_expression(value, state, import_map) -> set:
    """
    Evaluate an expression: bind walrus targets, then return
    the facts the expression produces.
    """

    for node in _walk_scope_local(value):
        if isinstance(node, ast.NamedExpr):
            state[node.target.id] = _produced_facts(
                node.value, state, import_map
            )

    return _subtree_facts(value, state, import_map)


def _produced_facts(value, state, import_map) -> frozenset:
    """
    Facts a right-hand value produces, applying a direct
    sanitizer call's sink-specific exemptions.

    Sanitizers nested inside larger expressions are not
    recognized: taint is preserved whenever safety cannot be
    established.
    """

    facts = _eval_expression(value, state, import_map)

    sanitizer = match_sanitizer(value, import_map)
    if sanitizer is not None:
        facts = {
            fact.with_cleared_sinks(sanitizer.clears_sinks)
            for fact in facts
        }

    return frozenset(facts)


def _bind_target(target, facts, state):
    """
    Bind an assignment target to a fact set, replacing the
    target's previous state. Other variables are untouched.
    """

    if isinstance(target, ast.Name):
        state[target.id] = facts

    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            _bind_target(element, facts, state)

    elif isinstance(target, ast.Starred):
        _bind_target(target.value, facts, state)

    # Attribute and Subscript targets bind names outside the
    # local scope and are intentionally not tracked.


def _pattern_names(pattern):
    """
    Return the names bound by one match pattern.
    """

    names = []

    for node in ast.walk(pattern):
        if isinstance(node, ast.MatchAs) and node.name:
            names.append(node.name)
        elif isinstance(node, ast.MatchStar) and node.name:
            names.append(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            names.append(node.rest)

    return names


def _first_loop_index(block):
    """
    Return the statement index of the loop header in a block,
    or None when the block contains no loop.

    The CFG builder makes every loop the last statement of its
    header block, so at most one loop per block exists.
    """

    for index, stmt in enumerate(block.statements):
        if isinstance(stmt, (ast.While, ast.For, ast.AsyncFor)):
            return index

    return None


def _join_states(first, second):
    """
    Union two taint states: per-name set union; a name present
    on only one path keeps that path's facts.
    """

    joined = dict(first)

    for name, facts in second.items():
        joined[name] = joined.get(name, frozenset()) | facts

    return joined


class _TaintSolver:
    """
    Fixpoint taint solver for one control flow graph.
    """

    def __init__(self, cfg, import_map=None):
        self.cfg = cfg
        self.import_map = import_map or {}
        self.in_states = {}
        self.out_states = {}

    def _is_back_edge(self, pred, block):
        """
        Check whether an edge re-enters a loop header.

        The CFG builder creates body blocks after their header,
        so every back edge points from a higher block ID into a
        block that owns a loop statement.
        """

        return (
            pred.block_id > block.block_id
            and _first_loop_index(block) is not None
        )

    def _back_edge_inputs(self, block):
        """
        Facts the loop body carries back into the header.
        """

        inputs = []

        for pred in block.predecessors:
            if not self._is_back_edge(pred, block):
                continue
            pred_out = self.out_states.get(pred.block_id)
            if pred_out is not None:
                inputs.append(pred_out)

        return inputs

    def solve(self):
        changed = True

        while changed:
            changed = False

            for block in self.cfg.blocks:

                normal_in = {}
                for pred in block.predecessors:
                    if self._is_back_edge(pred, block):
                        continue
                    pred_out = self.out_states.get(pred.block_id)
                    if pred_out is not None:
                        normal_in = _join_states(normal_in, pred_out)

                self.in_states[block.block_id] = normal_in

                new_out = self._transfer_block(
                    block,
                    normal_in,
                    self._back_edge_inputs(block),
                )

                if self.out_states.get(block.block_id) != new_out:
                    self.out_states[block.block_id] = new_out
                    changed = True

    def _transfer_block(
        self,
        block,
        in_state,
        back_edge_inputs,
        statement_observer=None,
    ):
        state = dict(in_state)

        loop_index = _first_loop_index(block)

        for index, stmt in enumerate(block.statements):

            if index == loop_index:
                for extra in back_edge_inputs:
                    state = _join_states(state, extra)

            if statement_observer is not None:
                statement_observer(stmt, state)

            self._transfer_statement(stmt, state)

        return state

    def collect_findings(self, file_path):
        """
        Observe every statement once with its stable fixpoint
        state and collect structured sink findings.

        One finding is emitted per distinct source origin
        reaching one sink; identical flows are deduplicated.
        """

        findings = []
        seen = set()

        for block in self.cfg.blocks:

            state = dict(self.in_states.get(block.block_id, {}))
            back_edge_inputs = self._back_edge_inputs(block)
            loop_index = _first_loop_index(block)

            for index, stmt in enumerate(block.statements):

                if index == loop_index:
                    for extra in back_edge_inputs:
                        state = _join_states(state, extra)

                self._observe_statement(
                    stmt, state, file_path, findings, seen
                )
                self._transfer_statement(stmt, state)

        findings.sort(
            key=lambda finding: (
                finding.rule_id,
                finding.sink_line,
                finding.source_line,
                finding.source_id,
            )
        )

        return findings

    def _observe_statement(self, stmt, state, file_path, findings, seen):
        """
        Report every registered sink reached by dangerous taint
        in this statement's own expressions.
        """

        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Nested bodies have their own CFG and are observed
            # there; no facts cross the scope boundary.
            return

        for top_node in _iter_own_expressions(stmt):
            for node in _walk_scope_local(top_node):

                if not isinstance(node, ast.Call):
                    continue

                for sink in match_sinks(node, self.import_map):
                    self._emit_sink_finding(
                        sink,
                        node,
                        state,
                        file_path,
                        findings,
                        seen,
                    )

    def _emit_sink_finding(
        self, sink, call_node, state, file_path, findings, seen
    ):
        """
        Emit one finding per distinct dangerous source origin
        reaching this sink call.
        """

        checked = list(call_node.args) + [
            keyword.value for keyword in call_node.keywords
        ]

        dangerous_by_origin = {}

        for expr in checked:
            for fact in _produced_facts(expr, state, self.import_map):
                if not fact.is_dangerous_for(sink.sink_kind):
                    continue
                dangerous_by_origin[
                    (fact.source_id, fact.source_line)
                ] = fact

        for (source_id, source_line), fact in dangerous_by_origin.items():

            key = (sink.rule_id, call_node.lineno, source_id, source_line)
            if key in seen:
                continue
            seen.add(key)

            findings.append(
                sink.create_finding(
                    node=call_node,
                    file_path=file_path,
                    function=self.cfg.name,
                    fact=fact,
                )
            )

    def _transfer_statement(self, stmt, state):

        if isinstance(stmt, ast.Assign):
            facts = _produced_facts(stmt.value, state, self.import_map)
            for target in stmt.targets:
                _bind_target(target, facts, state)
            return

        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                facts = _produced_facts(stmt.value, state, self.import_map)
                _bind_target(stmt.target, facts, state)
            return

        if isinstance(stmt, ast.AugAssign):
            if isinstance(stmt.target, ast.Name):
                old_facts = state.get(stmt.target.id, frozenset())
                facts = _produced_facts(
                    stmt.value, state, self.import_map
                ) | old_facts
                state[stmt.target.id] = frozenset(facts)
            else:
                _produced_facts(stmt.value, state, self.import_map)
            return

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            facts = _produced_facts(stmt.iter, state, self.import_map)
            _bind_target(stmt.target, facts, state)
            return

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                facts = _produced_facts(
                    item.context_expr, state, self.import_map
                )
                if item.optional_vars is not None:
                    _bind_target(item.optional_vars, facts, state)
            return

        if isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    state.pop(target.id, None)
            return

        if isinstance(stmt, ast.Match):
            facts = _produced_facts(stmt.subject, state, self.import_map)
            for case in stmt.cases:
                for name in _pattern_names(case.pattern):
                    state[name] = facts
            return

        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            state[stmt.name] = frozenset()
            return

        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                bound_name = alias.asname or alias.name.split(".")[0]
                state[bound_name] = frozenset()
            return

        if isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                if alias.name == "*":
                    continue
                state[alias.asname or alias.name] = frozenset()
            return

        if isinstance(stmt, (ast.Global, ast.Nonlocal)):
            return

        if isinstance(stmt, ast.ExceptHandler):
            if stmt.type is not None:
                _produced_facts(stmt.type, state, self.import_map)
            return

        # Remaining statements only evaluate their own header
        # expressions; bind any walrus targets in them.
        for top_node in _iter_own_expressions(stmt):
            for node in _walk_scope_local(top_node):
                if isinstance(node, ast.NamedExpr):
                    state[node.target.id] = _produced_facts(
                        node.value, state, self.import_map
                    )


def _collect_import_map(syntax_tree):
    """
    Static import bindings for the module: local name to fully
    qualified target.

    Built only from explicit import statements; relative and
    star imports add no bindings, and dynamic aliases are never
    guessed.
    """

    import_map = {}

    for node in ast.walk(syntax_tree):

        if isinstance(node, ast.Import):
            for alias in node.names:
                bound_name = alias.asname or alias.name.split(".")[0]
                import_map[bound_name] = alias.name.split(".")[0]

        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound_name = alias.asname or alias.name
                import_map[bound_name] = f"{node.module}.{alias.name}"

    return import_map


def analyze_taint(syntax_tree: ast.AST, file_path: str = "<unknown>") -> dict:
    """
    Run taint propagation and sink analysis for the module body
    and every function of a parsed module.

    Returns a mapping from qualified name ("&lt;module&gt;",
    "function", "Class.method") to FunctionTaintResult.
    """

    cfgs = build_cfgs(syntax_tree)
    import_map = _collect_import_map(syntax_tree)

    results = {}

    for qualname, cfg in cfgs.items():

        solver = _TaintSolver(cfg, import_map)
        solver.solve()

        exit_state = solver.in_states.get(solver.cfg.exit.block_id, {})

        results[qualname] = FunctionTaintResult(
            function_name=qualname,
            tainted_variables=dict(exit_state),
            findings=solver.collect_findings(file_path),
        )

    return results
