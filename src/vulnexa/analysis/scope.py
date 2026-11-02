
"""
Variable and scope tracking for Vulnexa.

Records which names each scope defines and references, then
reports names that are referenced but never defined (best
effort) and local variables that are assigned but never used.

Python's actual name resolution rules are respected:
- Function scopes can read enclosing function scopes.
- Class scopes are not visible inside their own methods.
- Names declared global/nonlocal resolve outside the scope.
- Builtins are always available.

This module only reads the AST; scanned source code is never
executed.
"""

import ast
import builtins
from dataclasses import dataclass, field


SCOPE_MODULE = "module"
SCOPE_FUNCTION = "function"
SCOPE_CLASS = "class"
SCOPE_LAMBDA = "lambda"
SCOPE_COMPREHENSION = "comprehension"

# Module-level dunder names provided by the interpreter.
MODULE_DUNDERS = {
    "__name__",
    "__file__",
    "__doc__",
    "__package__",
    "__spec__",
    "__loader__",
    "__builtins__",
    "__debug__",
    "__annotations__",
    "__qualname__",
}

BUILTIN_NAMES = set(dir(builtins)) | MODULE_DUNDERS


@dataclass
class ScopeInfo:
    """
    Definition and reference information for one scope.
    """

    scope_id: int
    name: str
    qualname: str
    kind: str
    line_number: int
    parent_id: int = None
    definitions: dict = field(default_factory=dict)
    references: dict = field(default_factory=dict)
    parameters: set = field(default_factory=set)
    star_import: bool = False
    global_names: set = field(default_factory=set)
    nonlocal_names: set = field(default_factory=set)

    def define(self, name: str, line_number: int):
        self.definitions.setdefault(name, []).append(line_number)

    def reference(self, name: str, line_number: int):
        self.references.setdefault(name, []).append(line_number)


@dataclass
class NameIssue:
    """
    A best-effort name-resolution warning.
    """

    scope_qualname: str
    name: str
    line_number: int
    kind: str


@dataclass
class ScopeAnalysisResult:
    """
    Full result of scope analysis for one module.
    """

    scopes: list = field(default_factory=list)
    undefined_references: list = field(default_factory=list)
    unused_variables: list = field(default_factory=list)

    def find_scope(self, qualname: str):
        """
        Return the ScopeInfo with the given qualified name.
        """

        for scope in self.scopes:
            if scope.qualname == qualname:
                return scope

        return None


class ScopeAnalyzer(ast.NodeVisitor):
    """
    Tracks scopes, variable definitions, and name references.
    """

    def __init__(self):
        self.result = ScopeAnalysisResult()
        self._stack = []

    # -- scope management -----------------------------------------

    def _open_scope(self, name, kind, node):
        parent = self._stack[-1] if self._stack else None

        if parent is None or parent.kind == SCOPE_MODULE:
            qualname = name
        else:
            qualname = f"{parent.qualname}.{name}"

        scope = ScopeInfo(
            scope_id=len(self.result.scopes),
            name=name,
            qualname=qualname,
            kind=kind,
            line_number=getattr(node, "lineno", 0),
            parent_id=parent.scope_id if parent else None,
        )

        self.result.scopes.append(scope)
        self._stack.append(scope)
        return scope

    def _close_scope(self):
        self._stack.pop()

    # -- name binding helpers --------------------------------------

    def _bind_target(self, target, line_number):
        if isinstance(target, ast.Name):
            self._current.define(target.id, line_number)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(element, line_number)
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value, line_number)
        # Attribute/Subscript targets bind outside local scope.

    def _bind_statement_names(self, node):
        """
        Record definitions introduced by a statement and count
        augmented assignments as both use and definition.
        """

        if isinstance(node, ast.Assign):
            for target in node.targets:
                self._bind_target(target, node.lineno)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None or isinstance(node.target, ast.Name):
                self._bind_target(node.target, node.lineno)
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name):
                self._current.reference(node.target.id, node.lineno)
                self._current.define(node.target.id, node.lineno)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self._bind_target(node.target, node.lineno)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    self._bind_target(item.optional_vars, node.lineno)
        elif isinstance(node, ast.NamedExpr):
            self._bind_target(node.target, node.lineno)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                self._current.define(node.name, node.lineno)
        elif isinstance(node, ast.TypeAlias):
            self._current.define(node.name, node.lineno)

    @property
    def _current(self) -> ScopeInfo:
        return self._stack[-1]

    # -- visitors ---------------------------------------------------

    def visit_Module(self, node):
        self._open_scope("<module>", SCOPE_MODULE, node)
        self.generic_visit(node)
        self._close_scope()

    def visit_FunctionDef(self, node):
        self._current.define(node.name, node.lineno)

        self._open_scope(node.name, SCOPE_FUNCTION, node)
        self._bind_arguments(node)
        self.generic_visit(node)
        self._close_scope()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._current.define(node.name, node.lineno)

        self._open_scope(node.name, SCOPE_CLASS, node)
        self.generic_visit(node)
        self._close_scope()

    def visit_Lambda(self, node):
        self._open_scope("<lambda>", SCOPE_LAMBDA, node)
        self._bind_arguments(node)
        self.generic_visit(node)
        self._close_scope()

    def _bind_arguments(self, node):
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

        for argument in all_args:
            self._current.define(argument.arg, node.lineno)
            self._current.parameters.add(argument.arg)

    def _visit_comprehension(self, node):
        self._open_scope("<comprehension>", SCOPE_COMPREHENSION, node)

        # Iteration variables live in the comprehension scope.
        for generator in node.generators:
            self._bind_target(generator.target, node.lineno)

        self.generic_visit(node)
        self._close_scope()

    def visit_ListComp(self, node):
        self._visit_comprehension(node)

    def visit_SetComp(self, node):
        self._visit_comprehension(node)

    def visit_DictComp(self, node):
        self._visit_comprehension(node)

    def visit_GeneratorExp(self, node):
        self._visit_comprehension(node)

    # -- statements that bind names -----------------------------------

    def visit_Import(self, node):
        for alias in node.names:
            bound_name = alias.asname or alias.name.split(".")[0]
            self._current.define(bound_name, node.lineno)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name == "*":
                self._current.star_import = True
                continue
            self._current.define(alias.asname or alias.name, node.lineno)

    def visit_Global(self, node):
        self._current.global_names.update(node.names)

    def visit_Nonlocal(self, node):
        self._current.nonlocal_names.update(node.names)

    def visit_Delete(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._current.define(target.id, node.lineno)
        self.generic_visit(node)

    # -- generic statement/expr handling -------------------------------

    def generic_visit(self, node):
        # Statements may bind names; record bindings, then keep
        # traversing so contained expressions register uses.
        # ExceptHandler is a separate node type (not ast.stmt)
        # but also binds names.
        if isinstance(node, (ast.stmt, ast.ExceptHandler)):
            self._bind_statement_names(node)

        super().generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            self._current.reference(node.id, node.lineno)


def _resolve_chain(scope: ScopeInfo, scopes_by_id: dict):
    """
    Build the lookup chain for a scope following Python rules.

    Class scopes are invisible to name lookups from scopes
    nested inside them, but a class body itself can read
    enclosing function scopes (closures).
    """

    chain = [scope]
    current = scope

    while current.parent_id is not None:
        parent = scopes_by_id[current.parent_id]

        if parent.kind != SCOPE_CLASS:
            chain.append(parent)

        current = parent

    return chain


def analyze_scopes(syntax_tree: ast.AST) -> ScopeAnalysisResult:
    """
    Analyze scopes and variables in a parsed module.
    """

    analyzer = ScopeAnalyzer()
    analyzer.visit(syntax_tree)

    result = analyzer.result
    scopes_by_id = {scope.scope_id: scope for scope in result.scopes}

    _detect_undefined_references(result, scopes_by_id)
    _detect_unused_variables(result)

    return result


def _detect_undefined_references(result, scopes_by_id):
    for scope in result.scopes:
        if scope.star_import:
            # Star imports can define any name; skip reporting.
            continue

        chain_names = []
        for chain_scope in _resolve_chain(scope, scopes_by_id):
            chain_names.append(set(chain_scope.definitions))

        for name, lines in scope.references.items():
            if name in scope.global_names or name in scope.nonlocal_names:
                continue

            if name in BUILTIN_NAMES:
                continue

            defined_anywhere = any(
                name in names for names in chain_names
            )
            if not defined_anywhere:
                for line_number in lines:
                    result.undefined_references.append(
                        NameIssue(
                            scope_qualname=scope.qualname,
                            name=name,
                            line_number=line_number,
                            kind="undefined",
                        )
                    )


def _detect_unused_variables(result):
    """
    Report local variables that are assigned but never read in
    their scope or any nested scope.

    Module-level names are treated as exported API and skipped,
    as are names starting with an underscore.
    """

    for scope in result.scopes:
        if scope.kind in (SCOPE_MODULE, SCOPE_CLASS):
            # Module names are exported API; class-body names are
            # methods/attributes referenced externally.
            continue

        # Collect references from this scope and all descendants.
        descendant_references = set()

        def collect(current):
            descendant_references.update(current.references.keys())
            for child in _child_scopes(result, current):
                collect(child)

        collect(scope)

        for name, lines in scope.definitions.items():
            if name.startswith("_"):
                continue

            if name in scope.parameters:
                continue

            if name in scope.global_names or name in scope.nonlocal_names:
                continue

            if name in descendant_references:
                continue

            for line_number in lines:
                result.unused_variables.append(
                    NameIssue(
                        scope_qualname=scope.qualname,
                        name=name,
                        line_number=line_number,
                        kind="unused",
                    )
                )


def _child_scopes(result, scope):
    for candidate in result.scopes:
        if candidate.parent_id == scope.scope_id:
            yield candidate
