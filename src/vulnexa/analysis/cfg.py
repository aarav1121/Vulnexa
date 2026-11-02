
"""
Control Flow Graph (CFG) construction for Vulnexa.

Builds a basic-block CFG for the module body and for every
function and method, including nested functions.

The construction is pragmatic rather than fully formal:
- Each basic block holds a linear run of statements.
- Branches (if/while/for/match/try) create edges between blocks.
- Return/Raise/Break/Continue terminate their block.
- Statements after a terminator are still recorded, but in an
  unreachable block (no incoming edges).
- Exceptional control flow is approximated: every non-terminated
  block inside a try body gains an edge to each except handler.
- match guards are not evaluated; a fall-through edge from the
  match header to the merge block is always present.

This module only reads the AST; scanned source code is never
executed.
"""

import ast
from dataclasses import dataclass, field


TERMINATOR_STATEMENTS = (
    ast.Return,
    ast.Raise,
    ast.Break,
    ast.Continue,
)


@dataclass
class BasicBlock:
    """
    A linear run of statements with explicit control edges.
    """

    block_id: int
    statements: list = field(default_factory=list)
    successors: list = field(default_factory=list)
    predecessors: list = field(default_factory=list)

    @property
    def is_terminated(self) -> bool:
        """
        Check whether the block ends with an unconditional
        control transfer.
        """

        if not self.statements:
            return False

        return isinstance(self.statements[-1], TERMINATOR_STATEMENTS)

    @property
    def is_unreachable(self) -> bool:
        return not self.predecessors


@dataclass
class ControlFlowGraph:
    """
    A complete CFG for one function or the module body.
    """

    name: str
    entry: BasicBlock
    exit: BasicBlock
    blocks: list = field(default_factory=list)

    def block_count(self) -> int:
        return len(self.blocks)

    def edge_count(self) -> int:
        return sum(
            len(block.successors)
            for block in self.blocks
        )

    def find_block(self, block_id: int):
        """
        Return the block with the given ID.
        """

        for block in self.blocks:
            if block.block_id == block_id:
                return block

        return None


class _LoopContext:
    """
    Tracks the break/continue targets of the innermost loop.
    """

    def __init__(self, break_target, continue_target):
        self.break_target = break_target
        self.continue_target = continue_target


class CFGBuilder:
    """
    Builds one ControlFlowGraph for a statement list.
    """

    def __init__(self):
        self.blocks = []
        self.loop_stack = []
        self._exit = None

    # -- structure helpers ----------------------------------------

    def new_block(self) -> BasicBlock:
        block = BasicBlock(block_id=len(self.blocks))
        self.blocks.append(block)
        return block

    def add_edge(self, source: BasicBlock, target: BasicBlock):
        if target not in source.successors:
            source.successors.append(target)
        if source not in target.predecessors:
            target.predecessors.append(source)

    def link(self, open_blocks, target: BasicBlock):
        for block in open_blocks:
            self.add_edge(block, target)

    # -- entry point -----------------------------------------------

    def build(self, name: str, body: list) -> ControlFlowGraph:
        entry = self.new_block()
        exit_block = self.new_block()
        self._exit = exit_block

        open_blocks = self.process(body, entry)
        self.link(open_blocks, exit_block)

        return ControlFlowGraph(
            name=name,
            entry=entry,
            exit=exit_block,
            blocks=self.blocks,
        )

    # -- statement list processing -----------------------------------

    def process(self, statements: list, current: BasicBlock) -> list:
        """
        Process a statement list starting at `current`.

        Returns the list of blocks that can fall through past the
        end of the list.
        """

        for statement in statements:

            if current is None:
                # Unreachable code: recorded but not connected.
                current = self.new_block()

            current = self._process_statement(statement, current)

        return [current] if current is not None else []

    def _process_statement(self, stmt, current: BasicBlock):
        """
        Process one statement and return the block that control
        falls into afterwards (or None when terminated).
        """

        if isinstance(stmt, (ast.Return, ast.Raise)):
            current.statements.append(stmt)
            self.add_edge(current, self._exit_block)
            return None

        if isinstance(stmt, ast.Break):
            current.statements.append(stmt)
            self.add_edge(current, self.loop_stack[-1].break_target)
            return None

        if isinstance(stmt, ast.Continue):
            current.statements.append(stmt)
            self.add_edge(current, self.loop_stack[-1].continue_target)
            return None

        if isinstance(stmt, ast.If):
            return self._process_if(stmt, current)

        if isinstance(stmt, (ast.While,)):
            return self._process_while(stmt, current)

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            return self._process_for(stmt, current)

        if isinstance(stmt, (ast.Try, ast.TryStar)):
            return self._process_try(stmt, current)

        if isinstance(stmt, ast.Match):
            return self._process_match(stmt, current)

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            current.statements.append(stmt)
            open_blocks = self.process(stmt.body, current)
            return open_blocks[0] if open_blocks else None

        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Nested definitions get their own CFG; the definition
            # statement itself is a simple step in this block.
            current.statements.append(stmt)
            return current

        # Every remaining statement type is a simple step.
        current.statements.append(stmt)
        return current

    # -- control constructs -----------------------------------------

    def _process_if(self, stmt: ast.If, current: BasicBlock):
        current.statements.append(stmt)

        after = self.new_block()
        then_start = self.new_block()

        self.add_edge(current, then_start)

        then_open = self.process(stmt.body, then_start)
        self.link(then_open, after)

        if stmt.orelse:
            else_start = self.new_block()
            self.add_edge(current, else_start)

            else_open = self.process(stmt.orelse, else_start)
            self.link(else_open, after)
        else:
            self.add_edge(current, after)

        return after

    def _process_while(self, stmt: ast.While, current: BasicBlock):
        current.statements.append(stmt)

        header = current
        after = self.new_block()
        body_start = self.new_block()

        self.add_edge(header, body_start)

        # With an else clause, normal exhaustion must flow
        # through it: no direct header -> after edge. break
        # still targets "after" and therefore skips the clause.
        if not stmt.orelse:
            self.add_edge(header, after)

        self.loop_stack.append(
            _LoopContext(break_target=after, continue_target=header)
        )

        body_open = self.process(stmt.body, body_start)
        self.loop_stack.pop()

        self.link(body_open, header)

        if stmt.orelse:
            else_start = self.new_block()
            self.add_edge(header, else_start)

            else_open = self.process(stmt.orelse, else_start)
            self.link(else_open, after)

        return after

    def _process_for(self, stmt, current: BasicBlock):
        current.statements.append(stmt)

        header = current
        after = self.new_block()
        body_start = self.new_block()

        self.add_edge(header, body_start)

        # With an else clause, normal exhaustion must flow
        # through it: no direct header -> after edge. break
        # still targets "after" and therefore skips the clause.
        if not stmt.orelse:
            self.add_edge(header, after)

        self.loop_stack.append(
            _LoopContext(break_target=after, continue_target=header)
        )

        body_open = self.process(stmt.body, body_start)
        self.loop_stack.pop()

        self.link(body_open, header)

        if stmt.orelse:
            else_start = self.new_block()
            self.add_edge(header, else_start)

            else_open = self.process(stmt.orelse, else_start)
            self.link(else_open, after)

        return after

    def _process_try(self, stmt, current: BasicBlock):
        current.statements.append(stmt)

        body_start = self.new_block()
        self.add_edge(current, body_start)

        blocks_before = len(self.blocks)
        body_open = self.process(stmt.body, body_start)

        # Include the starting block: any statement in the try
        # body may raise, including the first one.
        body_blocks = [body_start] + self.blocks[blocks_before:]

        handler_starts = []
        handler_open_all = []

        for handler in stmt.handlers:
            handler_start = self.new_block()
            handler_start.statements.append(handler)
            handler_starts.append(handler_start)

            handler_open = self.process(handler.body, handler_start)
            handler_open_all.extend(handler_open)

        # Approximate exceptional edges from the try body.
        for block in body_blocks:
            if not block.is_terminated:
                for handler_start in handler_starts:
                    self.add_edge(block, handler_start)

        after = self.new_block()

        if stmt.orelse:
            else_start = self.new_block()
            self.link(body_open, else_start)

            normal_open = self.process(stmt.orelse, else_start)
        else:
            normal_open = body_open

        if stmt.finalbody:
            finally_start = self.new_block()
            self.link(normal_open, finally_start)
            self.link(handler_open_all, finally_start)

            finally_open = self.process(stmt.finalbody, finally_start)
            self.link(finally_open, after)
        else:
            self.link(normal_open, after)
            self.link(handler_open_all, after)

        return after

    def _process_match(self, stmt: ast.Match, current: BasicBlock):
        current.statements.append(stmt)

        after = self.new_block()

        for case in stmt.cases:
            case_start = self.new_block()
            self.add_edge(current, case_start)

            case_open = self.process(case.body, case_start)
            self.link(case_open, after)

        # The subject may match no case at all.
        self.add_edge(current, after)

        return after

    # -- exit-block access ------------------------------------------

    @property
    def _exit_block(self) -> BasicBlock:
        return self._exit


def _collect_functions(syntax_tree: ast.AST):
    """
    Find every function with its qualified name, preserving
    nesting order.
    """

    functions = []
    stack = []

    class Collector(ast.NodeVisitor):

        def visit_FunctionDef(self, node):
            qualname = ".".join(stack + [node.name])
            functions.append((qualname, node))

            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_ClassDef(self, node):
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

    Collector().visit(syntax_tree)
    return functions


def build_cfgs(syntax_tree: ast.AST) -> dict:
    """
    Build CFGs for the module body and every function.

    Returns a mapping from qualified name ("&lt;module&gt;",
    "function", "Class.method") to its ControlFlowGraph.
    """

    cfgs = {}

    module_cfg = CFGBuilder().build("<module>", syntax_tree.body)
    cfgs["<module>"] = module_cfg

    for qualname, function_node in _collect_functions(syntax_tree):
        cfg = CFGBuilder().build(qualname, function_node.body)
        cfgs[qualname] = cfg

    return cfgs
