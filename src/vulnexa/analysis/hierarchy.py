
"""
Function and class relationship analysis for Vulnexa.

Collects:
- Class definitions with their base classes and methods.
- Function definitions with the names they call.
- A call graph and its reverse (who calls whom).

Name resolution is intentionally kept simple: calls are matched
by their written name (e.g. "helper", "self.run", "os.system").
Dynamic or aliased calls cannot be resolved statically at this
stage and are documented as a limitation.

This module only reads the AST; scanned source code is never
executed.
"""

import ast
from dataclasses import dataclass, field


@dataclass
class ClassInfo:
    """
    A class definition and its relationships.
    """

    name: str
    qualname: str
    line_number: int
    bases: list = field(default_factory=list)
    methods: list = field(default_factory=list)


@dataclass
class FunctionInfo:
    """
    A function or method definition and its outgoing calls.
    """

    name: str
    qualname: str
    line_number: int
    is_method: bool = False
    parent_class: str = ""
    calls: set = field(default_factory=set)


@dataclass
class HierarchyResult:
    """
    Class and call relationships for one module.
    """

    classes: dict = field(default_factory=dict)
    functions: dict = field(default_factory=dict)
    call_graph: dict = field(default_factory=dict)
    reverse_call_graph: dict = field(default_factory=dict)

    def get_subclasses(self, class_name: str) -> list:
        """
        Return classes whose bases include the given class name.
        """

        return [
            info
            for info in self.classes.values()
            if class_name in info.bases
        ]

    def get_callers(self, callee_name: str) -> set:
        """
        Return every function qualname that calls callee_name.
        """

        return self.reverse_call_graph.get(callee_name, set())


class RelationshipAnalyzer(ast.NodeVisitor):
    """
    Collects class hierarchy and call-graph information.
    """

    def __init__(self):
        self.result = HierarchyResult()
        self._stack = []

    # -- helpers -------------------------------------------------

    @property
    def _current_qualname(self) -> str:
        if not self._stack:
            return "<module>"
        return ".".join(
            name for name, _ in self._stack
        )

    def _is_inside_class(self) -> bool:
        return bool(self._stack) and self._stack[-1][1] == "class"

    def _qualified_name(self, node) -> str:
        """
        Render a called expression as a readable dotted string.
        """

        if isinstance(node, ast.Name):
            return node.id

        if isinstance(node, ast.Attribute):
            base = self._qualified_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr

        return ""

    def _record_call(self, call_node):
        callee = self._qualified_name(call_node.func)
        if not callee:
            return

        current = self._current_qualname
        function_info = self.result.functions.get(current)

        if function_info is not None:
            function_info.calls.add(callee)
        else:
            # Calls made at module or class-body level.
            module_info = self.result.functions.setdefault(
                current,
                FunctionInfo(
                    name=current,
                    qualname=current,
                    line_number=call_node.lineno,
                )
            )
            module_info.calls.add(callee)

        self.result.reverse_call_graph.setdefault(callee, set()).add(current)

    # -- visitors ---------------------------------------------------

    def visit_ClassDef(self, node):
        bases = []
        for base in node.bases:
            rendered = self._qualified_name(base)
            if rendered:
                bases.append(rendered)

        info = ClassInfo(
            name=node.name,
            qualname=self._current_qualname_for_child(node.name),
            line_number=node.lineno,
            bases=bases,
        )

        self.result.classes[info.qualname] = info

        self._stack.append((node.name, "class"))
        self.generic_visit(node)
        self._stack.pop()

    def visit_FunctionDef(self, node):
        is_method = self._is_inside_class()
        parent_class = ""

        if is_method:
            parent_class = self._stack[-1][0]
            class_qualname = self._current_qualname
            class_info = self.result.classes.get(class_qualname)
            if class_info is not None:
                class_info.methods.append(node.name)

        qualname = self._current_qualname_for_child(node.name)

        info = FunctionInfo(
            name=node.name,
            qualname=qualname,
            line_number=node.lineno,
            is_method=is_method,
            parent_class=parent_class,
        )

        self.result.functions[qualname] = info

        self._stack.append((node.name, "function"))
        self.generic_visit(node)
        self._stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        self._record_call(node)
        self.generic_visit(node)

    # -- helpers used by visitors -------------------------------------

    def _current_qualname_for_child(self, child_name: str) -> str:
        if not self._stack:
            return child_name
        return f"{self._current_qualname}.{child_name}"


def analyze_relationships(syntax_tree: ast.AST) -> HierarchyResult:
    """
    Analyze class and function relationships in a parsed module.
    """

    analyzer = RelationshipAnalyzer()
    analyzer.visit(syntax_tree)

    return analyzer.result
