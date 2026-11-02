
"""
Data-flow analysis for Vulnexa.

Computes reaching definitions over the control flow graph of
every function (and the module body), then derives:

- Def-use chains: where each variable definition is used.
- Use-before-definition warnings for local variables.

The analysis is a conservative "may" analysis: a definition
reaches a use when at least one path leads there. Loop back
edges are resolved to a fixpoint.

Only names assigned inside the analyzed function are checked,
so reads of globals, builtins, and parameters never produce
false use-before-definition warnings.

This module only reads the AST; scanned source code is never
executed.
"""

import ast
from dataclasses import dataclass, field

from vulnexa.analysis.cfg import build_cfgs
from vulnexa.analysis.scope import BUILTIN_NAMES


SKIP_SUBTREE_NODES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.ClassDef,
    ast.Lambda,
)


@dataclass
class Definition:
    """
    One assignment point for a variable.
    """

    name: str
    block_id: int
    line_number: int
    index: int


@dataclass
class UsePoint:
    """
    One read of a variable.
    """

    name: str
    block_id: int
    line_number: int


@dataclass
class DataFlowResult:
    """
    Data-flow facts for one function or module body.
    """

    function_name: str
    definitions: dict = field(default_factory=dict)
    use_before_definition: list = field(default_factory=list)
    def_use_chains: dict = field(default_factory=dict)

    def get_definitions(self, name: str) -> list:
        """
        Return every definition of a variable.
        """

        return self.definitions.get(name, [])


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


def _iter_header_nodes(stmt):
    """
    Yield the expression nodes a statement evaluates itself.

    Statements that own nested statement lists (if/while/for/
    with/try/match) are analyzed as separate blocks, so only
    their header expressions belong to this statement's facts.
    """

    if isinstance(stmt, ast.If):
        yield from _walk_scope_local(stmt.test)

    elif isinstance(stmt, ast.While):
        yield from _walk_scope_local(stmt.test)

    elif isinstance(stmt, (ast.For, ast.AsyncFor)):
        yield from _walk_scope_local(stmt.iter)
        yield from _walk_scope_local(stmt.target)

    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        for item in stmt.items:
            yield from _walk_scope_local(item.context_expr)
            if item.optional_vars is not None:
                yield from _walk_scope_local(item.optional_vars)

    elif isinstance(stmt, ast.Match):
        yield from _walk_scope_local(stmt.subject)
        for case in stmt.cases:
            yield from _walk_scope_local(case.pattern)

    elif isinstance(stmt, (ast.Try, ast.TryStar)):
        # Nothing is evaluated by the try header itself.
        pass

    else:
        yield from _walk_scope_local(stmt)


def _statement_uses_and_defs(stmt):
    """
    Split one statement into name uses, name definitions, and
    name deletions.

    Returns three lists of (name, line_number) tuples. Uses are
    listed first because they are evaluated before the targets
    of the same statement are assigned. Deletions are kept
    separate from definitions: `del x` removes the binding of
    x without creating one.
    """

    uses = []
    defs = []
    kills = []

    # A nested definition binds its own name in this scope.
    if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        defs.append((stmt.name, stmt.lineno))
        return uses, defs, kills

    # An exception handler binds its name; only its type
    # expression is evaluated here (the body statements are
    # analyzed as their own facts).
    if isinstance(stmt, ast.ExceptHandler):
        if stmt.type is not None:
            for node in _walk_scope_local(stmt.type):
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    uses.append((node.id, node.lineno))
        if stmt.name:
            defs.append((stmt.name, stmt.lineno))
        return uses, defs, kills

    for node in _iter_header_nodes(stmt):

        if isinstance(node, ast.Name):
            if isinstance(node.ctx, ast.Load):
                uses.append((node.id, node.lineno))
            elif isinstance(node.ctx, ast.Store):
                defs.append((node.id, node.lineno))
            elif isinstance(node.ctx, ast.Del):
                kills.append((node.id, node.lineno))

        elif isinstance(node, ast.MatchAs):
            if node.name:
                defs.append((node.name, stmt.lineno))

        elif isinstance(node, ast.MatchStar):
            if node.name:
                defs.append((node.name, stmt.lineno))

        elif isinstance(node, ast.MatchMapping):
            if node.rest:
                defs.append((node.rest, stmt.lineno))

    # Augmented assignment both reads and writes its target.
    if isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
        uses.append((stmt.target.id, stmt.lineno))

    return uses, defs, kills


class _FunctionFacts:
    """
    Collects parameters and global/nonlocal declarations per
    qualified function name.
    """

    def __init__(self):
        self.params = {}
        self.declared_global = {}
        self.declared_nonlocal = {}
        self._stack = []

    def collect(self, syntax_tree: ast.AST):

        class Collector(ast.NodeVisitor):

            def visit_FunctionDef(inner_self, node):
                qualname = ".".join(self._stack + [node.name])
                arguments = node.args

                all_args = (
                    list(arguments.posonlyargs)
                    + list(arguments.args)
                    + list(arguments.kwonlyargs)
                )
                if arguments.vararg:
                    all_args.append(arguments.vararg)
                if arguments.kwarg:
                    all_args.append(arguments.kwarg)

                self.params[qualname] = [arg.arg for arg in all_args]
                self.declared_global.setdefault(qualname, set())
                self.declared_nonlocal.setdefault(qualname, set())

                self._stack.append(node.name)
                inner_self.generic_visit(node)
                self._stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(inner_self, node):
                self._stack.append(node.name)
                inner_self.generic_visit(node)
                self._stack.pop()

            def visit_Global(inner_self, node):
                qualname = (
                    ".".join(self._stack) if self._stack else "<module>"
                )
                self.declared_global.setdefault(qualname, set())
                self.declared_global[qualname].update(node.names)

            def visit_Nonlocal(inner_self, node):
                qualname = (
                    ".".join(self._stack) if self._stack else "<module>"
                )
                self.declared_nonlocal.setdefault(qualname, set())
                self.declared_nonlocal[qualname].update(node.names)

        Collector().visit(syntax_tree)


class ReachingDefinitions:
    """
    Reaching-definitions solver for one CFG.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.all_defs = []
        self.defs_by_var = {}
        self.block_defs = {}
        self.block_uses = {}
        self.gen = {}
        self.kill = {}
        self.entry_in = set()
        self._in = {}
        self._out = {}

    # -- construction ------------------------------------------------

    def build(self, params, function_line):

        # Parameter definitions live at the entry block.
        entry_defs = []
        for param_name in params:
            definition = Definition(
                name=param_name,
                block_id=self.cfg.entry.block_id,
                line_number=function_line,
                index=len(self.all_defs),
            )
            self._register(definition)
            entry_defs.append(definition)

        # Statement definitions and uses per block.
        for block in self.cfg.blocks:
            statement_facts = []

            for stmt in block.statements:
                uses, defs, kills = _statement_uses_and_defs(stmt)

                def_indices = []
                for name, line in defs:
                    definition = Definition(
                        name=name,
                        block_id=block.block_id,
                        line_number=line,
                        index=len(self.all_defs),
                    )
                    self._register(definition)
                    def_indices.append(definition)

                statement_facts.append((uses, def_indices, kills))

            # Parameter definitions act as the first fact of the
            # entry block so they are available to its statements.
            if block is self.cfg.entry and entry_defs:
                statement_facts.insert(0, ([], entry_defs, []))

            self.block_defs[block.block_id] = statement_facts

        self._compute_gen_kill()
        self._solve()

    def _register(self, definition: Definition):
        self.all_defs.append(definition)
        self.defs_by_var.setdefault(definition.name, []).append(definition)

    def _compute_gen_kill(self):
        for block in self.cfg.blocks:
            facts = self.block_defs.get(block.block_id, [])

            # Track the last event (definition or deletion) for
            # each variable in statement order: it decides what
            # leaves the block.
            last_event_per_var = {}
            for _uses, def_indices, kills in facts:
                for definition in def_indices:
                    last_event_per_var[definition.name] = ("def", definition)
                for name, _line in kills:
                    last_event_per_var[name] = ("kill", None)

            gen = set()
            kill = set()

            for name, (event, definition) in last_event_per_var.items():
                if event == "def":
                    gen.add(definition.index)
                    for other in self.defs_by_var[name]:
                        if other.index != definition.index:
                            kill.add(other.index)
                else:
                    # A deletion is a kill without a generation:
                    # no definition of the name leaves the block.
                    for other in self.defs_by_var.get(name, []):
                        kill.add(other.index)

            self.gen[block.block_id] = gen
            self.kill[block.block_id] = kill

    # -- fixpoint ------------------------------------------------------

    def _solve(self):
        in_sets = {
            block.block_id: set()
            for block in self.cfg.blocks
        }
        out_sets = {
            block.block_id: set()
            for block in self.cfg.blocks
        }

        changed = True
        while changed:
            changed = False

            for block in self.cfg.blocks:
                new_in = set()
                for pred in block.predecessors:
                    new_in |= out_sets[pred.block_id]

                new_out = self.gen[block.block_id] | (
                    new_in - self.kill[block.block_id]
                )

                if new_in != in_sets[block.block_id] or \
                        new_out != out_sets[block.block_id]:
                    in_sets[block.block_id] = new_in
                    out_sets[block.block_id] = new_out
                    changed = True

        self._in = in_sets
        self._out = out_sets

    def reaching_at_block(self, block_id: int) -> set:
        return set(self._in[block_id])


def analyze_function(
    cfg,
    params=(),
    function_line=0,
    global_names=frozenset(),
    nonlocal_names=frozenset(),
) -> DataFlowResult:
    """
    Compute data-flow facts for one control flow graph.
    """

    solver = ReachingDefinitions(cfg)
    solver.build(params=params, function_line=function_line)

    result = DataFlowResult(function_name=cfg.name)

    for definition in solver.all_defs:
        result.definitions.setdefault(definition.name, []).append(definition)

    local_vars = set(result.definitions.keys())
    external_names = set(global_names) | set(nonlocal_names)

    chains = {}

    for block in cfg.blocks:
        # Definitions reaching the start of this block.
        current = solver.reaching_at_block(block.block_id)

        facts = solver.block_defs.get(block.block_id, [])

        for uses, def_indices, kills in facts:

            # Names bound by the same statement (comprehension
            # iteration variables, walrus targets) legitimately
            # use themselves while being defined.
            same_statement_defs = {
                definition.name for definition in def_indices
            }

            for name, line in uses:
                use_point = UsePoint(
                    name=name,
                    block_id=block.block_id,
                    line_number=line,
                )

                reaching = [
                    solver.all_defs[index]
                    for index in current
                    if solver.all_defs[index].name == name
                ]

                for definition in reaching:
                    var_chains = chains.setdefault(name, {})
                    var_chains.setdefault(
                        definition.line_number, set()
                    ).add(line)

                if not reaching and name in local_vars:
                    is_external = name in external_names
                    is_builtin = name in BUILTIN_NAMES
                    is_bound_here = name in same_statement_defs
                    if not is_external and not is_builtin and not is_bound_here:
                        result.use_before_definition.append(use_point)

            for definition in def_indices:
                current = {
                    index
                    for index in current
                    if solver.all_defs[index].name != definition.name
                }
                current.add(definition.index)

            # Deletions kill reaching definitions without
            # creating new ones.
            for name, _line in kills:
                current = {
                    index
                    for index in current
                    if solver.all_defs[index].name != name
                }

    result.def_use_chains = chains

    return result


def analyze_tree(syntax_tree: ast.AST) -> dict:
    """
    Build CFGs and data-flow results for every function and the
    module body of a parsed module.

    Returns a mapping from qualified name to DataFlowResult.
    """

    cfgs = build_cfgs(syntax_tree)

    facts = _FunctionFacts()
    facts.collect(syntax_tree)

    results = {}

    for qualname, cfg in cfgs.items():

        function_line = 0
        if qualname != "<module>":
            function_line = _find_function_line(syntax_tree, qualname)

        results[qualname] = analyze_function(
            cfg,
            params=facts.params.get(qualname, ()),
            function_line=function_line,
            global_names=facts.declared_global.get(qualname, set()),
            nonlocal_names=facts.declared_nonlocal.get(qualname, set()),
        )

    return results


def _find_function_line(syntax_tree: ast.AST, qualname: str) -> int:

    class Collector(ast.NodeVisitor):

        def __init__(self):
            self.stack = []
            self.line = 0

        def _visit(self, node):
            qualname_candidate = ".".join(self.stack + [node.name])
            if qualname_candidate == qualname:
                self.line = node.lineno

            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_FunctionDef = _visit
        visit_AsyncFunctionDef = _visit

        def visit_ClassDef(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

    collector = Collector()
    collector.visit(syntax_tree)

    return collector.line
