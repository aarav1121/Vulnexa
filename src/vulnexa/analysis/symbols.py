
"""
Symbol analysis for Vulnexa.

Builds a hierarchical symbol table from a Python AST. Every
scope (module, function, class, comprehension, lambda) gets a
SymbolTable describing the names it defines.

This module only reads the AST; scanned source code is never
executed.
"""

import ast
from dataclasses import dataclass, field


SYMBOL_FUNCTION = "function"
SYMBOL_METHOD = "method"
SYMBOL_CLASS = "class"
SYMBOL_VARIABLE = "variable"
SYMBOL_PARAMETER = "parameter"
SYMBOL_IMPORT = "import"
SYMBOL_GLOBAL = "global"
SYMBOL_NONLOCAL = "nonlocal"

TABLE_MODULE = "module"
TABLE_FUNCTION = "function"
TABLE_CLASS = "class"
TABLE_LAMBDA = "lambda"
TABLE_COMPREHENSION = "comprehension"


@dataclass
class Symbol:
    """
    A single named symbol defined inside one scope.
    """

    name: str
    kind: str
    line_number: int
    scope_path: str
    detail: str = ""


@dataclass
class SymbolTable:
    """
    A scope in the hierarchical symbol table.
    """

    name: str
    kind: str
    line_number: int
    scope_path: str
    symbols: dict = field(default_factory=dict)
    children: list = field(default_factory=list)

    def add(self, symbol: Symbol):
        """
        Add or replace a symbol in this scope.
        """

        self.symbols[symbol.name] = symbol

    def has(self, name: str) -> bool:
        """
        Check whether a name is defined in this scope.
        """

        return name in self.symbols

    def walk(self):
        """
        Iterate this table and all nested tables depth-first.
        """

        yield self

        for child in self.children:
            yield from child.walk()

    def flatten(self) -> list:
        """
        Return every symbol in the table and its nested tables.
        """

        symbols = []

        for table in self.walk():
            symbols.extend(table.symbols.values())

        return symbols

    def find_scope(self, scope_path: str):
        """
        Return the nested table with the given scope path.
        """

        for table in self.walk():
            if table.scope_path == scope_path:
                return table

        return None


class SymbolTableBuilder(ast.NodeVisitor):
    """
    Builds a hierarchical SymbolTable from a parsed module.
    """

    def __init__(self):
        self.root = SymbolTable(
            name="<module>",
            kind=TABLE_MODULE,
            line_number=1,
            scope_path="",
        )

        self._stack = [self.root]
        self._anonymous_count = 0

    # -- helpers -------------------------------------------------

    @property
    def _current(self) -> SymbolTable:
        return self._stack[-1]

    def _scope_path(self, name: str) -> str:
        parent_path = self._current.scope_path
        if not parent_path:
            return name
        return f"{parent_path}.{name}"

    def _add(self, name, kind, node, detail=""):
        if not name:
            return

        self._current.add(
            Symbol(
                name=name,
                kind=kind,
                line_number=getattr(node, "lineno", 0),
                scope_path=self._current.scope_path,
                detail=detail,
            )
        )

    # -- scope-opening statements --------------------------------

    def _define_callable(self, node, is_class=False):
        parent_is_class = self._current.kind == TABLE_CLASS
        kind = SYMBOL_CLASS if is_class else (
            SYMBOL_METHOD if parent_is_class else SYMBOL_FUNCTION
        )

        self._add(node.name, kind, node)

        table = SymbolTable(
            name=node.name,
            kind=TABLE_CLASS if is_class else TABLE_FUNCTION,
            line_number=node.lineno,
            scope_path=self._scope_path(node.name),
        )

        self._current.children.append(table)
        self._stack.append(table)

        # Decorators, default arguments, and annotations are
        # evaluated in the enclosing scope, but recording them
        # as parameters keeps the table simple and predictable.
        if not is_class:
            self._collect_parameters(node)

        self.generic_visit(node)
        self._stack.pop()

    def _collect_parameters(self, node):
        arguments = node.args

        positional = list(arguments.posonlyargs) + list(arguments.args)
        keyword_only = list(arguments.kwonlyargs)

        for argument in positional + keyword_only:
            self._add(argument.arg, SYMBOL_PARAMETER, argument)

        if arguments.vararg:
            self._add(arguments.vararg.arg, SYMBOL_PARAMETER, arguments.vararg)

        if arguments.kwarg:
            self._add(arguments.kwarg.arg, SYMBOL_PARAMETER, arguments.kwarg)

    def visit_FunctionDef(self, node):
        self._define_callable(node)

    def visit_AsyncFunctionDef(self, node):
        self._define_callable(node)

    def visit_ClassDef(self, node):
        self._define_callable(node, is_class=True)

    def _anonymous_name(self, base: str) -> str:
        self._anonymous_count += 1
        return f"{base}{self._anonymous_count}"

    def visit_Lambda(self, node):
        name = self._anonymous_name("<lambda>")
        table = SymbolTable(
            name=name,
            kind=TABLE_LAMBDA,
            line_number=node.lineno,
            scope_path=self._scope_path(name),
        )

        self._current.children.append(table)
        self._stack.append(table)

        self._collect_parameters(node)
        self.generic_visit(node)
        self._stack.pop()

    def _define_comprehension(self, node):
        name = self._anonymous_name("<comp>")
        table = SymbolTable(
            name=name,
            kind=TABLE_COMPREHENSION,
            line_number=node.lineno,
            scope_path=self._scope_path(name),
        )

        self._current.children.append(table)
        self._stack.append(table)

        self.generic_visit(node)
        self._stack.pop()

    def visit_ListComp(self, node):
        self._define_comprehension(node)

    def visit_SetComp(self, node):
        self._define_comprehension(node)

    def visit_DictComp(self, node):
        self._define_comprehension(node)

    def visit_GeneratorExp(self, node):
        self._define_comprehension(node)

    # -- name-binding statements ----------------------------------

    def visit_Import(self, node):
        for alias in node.names:
            bound_name = alias.asname or alias.name.split(".")[0]
            self._add(bound_name, SYMBOL_IMPORT, node, detail=alias.name)

    def visit_ImportFrom(self, node):
        module = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                continue
            bound_name = alias.asname or alias.name
            detail = f"{module}.{alias.name}" if module else alias.name
            self._add(bound_name, SYMBOL_IMPORT, node, detail=detail)

    def visit_Global(self, node):
        for name in node.names:
            self._add(name, SYMBOL_GLOBAL, node)

    def visit_Nonlocal(self, node):
        for name in node.names:
            self._add(name, SYMBOL_NONLOCAL, node)

    def visit_Assign(self, node):
        for target in node.targets:
            self._bind_target(target, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        self._bind_target(node.target, node)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        self._bind_target(node.target, node)
        self.generic_visit(node)

    def visit_NamedExpr(self, node):
        self._bind_target(node.target, node)
        self.generic_visit(node)

    def visit_For(self, node):
        self._bind_target(node.target, node)
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_With(self, node):
        for item in node.items:
            if item.optional_vars is not None:
                self._bind_target(item.optional_vars, node)
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_ExceptHandler(self, node):
        if node.name:
            self._add(node.name, SYMBOL_VARIABLE, node)
        self.generic_visit(node)

    def visit_TypeAlias(self, node):
        self._add(node.name, SYMBOL_VARIABLE, node)
        self.generic_visit(node)

    def _bind_target(self, target, node):
        if isinstance(target, ast.Name):
            self._add(target.id, SYMBOL_VARIABLE, node)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(element, node)
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value, node)
        # Attribute and Subscript targets bind names outside the
        # local scope and are intentionally not recorded.


def collect_symbols(syntax_tree: ast.AST) -> SymbolTable:
    """
    Build the full symbol table for a parsed module.
    """

    builder = SymbolTableBuilder()
    builder.visit(syntax_tree)

    return builder.root
