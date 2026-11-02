
import ast

from vulnexa.analysis.cfg import build_cfgs


def build(code: str):
    return build_cfgs(ast.parse(code))


def last_statement(block):
    return block.statements[-1] if block.statements else None


def test_module_cfg_exists_with_entry_and_exit():
    cfgs = build("x = 1\n")

    assert "<module>" in cfgs
    cfg = cfgs["<module>"]

    assert cfg.entry is not cfg.exit
    assert cfg.entry.successors == [cfg.exit]


def test_linear_code_single_block():
    code = "a = 1\nb = 2\nc = a + b\n"

    cfg = build(code)["<module>"]

    # entry + exit only: all statements fall in the entry block.
    assert cfg.block_count() == 2
    assert len(cfg.entry.statements) == 3


def test_if_else_creates_branch_and_merge():
    code = (
        "if cond:\n"
        "    a = 1\n"
        "else:\n"
        "    a = 2\n"
        "b = 3\n"
    )

    cfg = build(code)["<module>"]

    entry = cfg.entry
    successors = entry.successors

    assert len(successors) == 2  # then and else branches

    merge = successors[0].successors[0]
    assert merge is cfg.exit or merge.successors == [cfg.exit]


def test_if_without_else_falls_through():
    code = (
        "if cond:\n"
        "    a = 1\n"
        "b = 2\n"
    )

    cfg = build(code)["<module>"]
    entry = cfg.entry

    assert len(entry.successors) == 2


def test_while_creates_back_edge():
    code = (
        "while cond:\n"
        "    work()\n"
        "done = True\n"
    )

    cfg = build(code)["<module>"]
    header = cfg.entry

    body = header.successors[0]

    assert header in body.successors  # back edge to loop header
    assert len(header.successors) == 2  # body + exit


def test_break_and_continue_targets():
    code = (
        "while True:\n"
        "    if cond:\n"
        "        break\n"
        "    if other:\n"
        "        continue\n"
    )

    cfg = build(code)["<module>"]

    break_edges = []
    continue_edges = []

    for block in cfg.blocks:
        for statement in block.statements:
            if isinstance(statement, ast.Break):
                break_edges.extend(block.successors)
            if isinstance(statement, ast.Continue):
                continue_edges.extend(block.successors)

    assert break_edges
    assert continue_edges

    # The continue target is the loop header (entry block).
    assert cfg.entry in continue_edges

    # The break target must not be the header.
    assert cfg.entry not in break_edges


def test_return_connects_to_exit():
    code = (
        "def f():\n"
        "    if cond:\n"
        "        return 1\n"
        "    return 2\n"
    )

    cfg = build(code)["f"]

    returns = []
    for block in cfg.blocks:
        for statement in block.statements:
            if isinstance(statement, ast.Return):
                returns.append(block)

    assert returns
    for block in returns:
        assert cfg.exit in block.successors


def test_unreachable_code_recorded_without_edges():
    code = (
        "def f():\n"
        "    return 1\n"
        "    dead = 2\n"
    )

    cfg = build(code)["f"]

    dead_blocks = [
        block for block in cfg.blocks
        if any(
            isinstance(stmt, ast.Assign) and getattr(stmt, 'lineno', 0) == 3
            for stmt in block.statements
        )
    ]

    assert dead_blocks
    assert dead_blocks[0].is_unreachable


def test_nested_functions_get_own_cfgs():
    code = (
        "def outer():\n"
        "    def inner():\n"
        "        return 1\n"
        "    return inner\n"
    )

    cfgs = build(code)

    assert "outer" in cfgs
    assert "outer.inner" in cfgs

    inner = cfgs["outer.inner"]
    assert len(inner.entry.statements) == 1


def test_try_connects_body_to_handler():
    code = (
        "try:\n"
        "    risky()\n"
        "except ValueError:\n"
        "    recover()\n"
    )

    cfg = build(code)["<module>"]

    handler_blocks = [
        block for block in cfg.blocks
        if block.statements
        and isinstance(block.statements[0], ast.ExceptHandler)
    ]

    body_blocks = [
        block for block in cfg.blocks
        if block.statements
        and isinstance(block.statements[0], ast.Expr)
    ]

    assert handler_blocks
    assert body_blocks

    # The body block gains an exceptional edge to the handler.
    assert handler_blocks[0] in body_blocks[0].successors


def test_function_cfgs_and_module_do_not_share_blocks():
    code = (
        "def f():\n"
        "    a = 1\n"
        "\n"
        "def g():\n"
        "    b = 2\n"
    )

    cfgs = build(code)

    assert cfgs["f"].blocks is not cfgs["g"].blocks
    assert len(cfgs["f"].blocks) == 2
    assert len(cfgs["g"].blocks) == 2


def test_for_loop_creates_back_edge():
    code = (
        "for item in items:\n"
        "    process(item)\n"
    )

    cfg = build(code)["<module>"]
    header = cfg.entry
    body = header.successors[0]

    assert header in body.successors


# --------------------------------------------------------------------------
# Loop-else control flow (for-else / while-else)
# --------------------------------------------------------------------------
#
# Python semantics: the else clause of a loop executes whenever the
# loop finishes by exhaustion (condition false / iterator empty) and
# is skipped entirely when a break statement executes.
#
# These tests verify the actual graph edges, not just that the
# builder runs.


def block_containing(cfg, line_number):
    """
    Return the block that holds the statement written at the
    given source line.
    """

    for block in cfg.blocks:
        for statement in block.statements:
            if getattr(statement, "lineno", None) == line_number:
                return block

    raise AssertionError(f"No block with a statement at line {line_number}")


def test_for_else_normal_completion_executes_else_clause():
    code = (
        "for item in items:\n"     # 1
        "    use(item)\n"          # 2
        "else:\n"                  # 3
        "    done = True\n"        # 4
        "report(done)\n"           # 5
    )

    cfg = build(code)["<module>"]
    header = cfg.entry
    body_block = block_containing(cfg, 2)
    else_block = block_containing(cfg, 4)
    after_block = block_containing(cfg, 5)

    # Header branches into the body and into the else clause.
    assert body_block in header.successors
    assert else_block in header.successors

    # Body loops back to the header.
    assert header in body_block.successors

    # Normal exhaustion runs the else clause, which then flows
    # into the code after the loop.
    assert after_block in else_block.successors


def test_for_else_normal_completion_no_direct_bypass_edge():
    code = (
        "for item in items:\n"     # 1
        "    use(item)\n"          # 2
        "else:\n"                  # 3
        "    done = True\n"        # 4
        "report(done)\n"           # 5
    )

    cfg = build(code)["<module>"]
    header = cfg.entry
    else_block = block_containing(cfg, 4)
    after_block = block_containing(cfg, 5)

    assert after_block in else_block.successors

    # Strict Python semantics: on normal exhaustion the else
    # clause ALWAYS runs, so the only non-break path from the
    # header into the after-loop block must go through the else
    # block. A direct header -> after edge would describe a
    # control path that cannot happen in real Python.
    assert header not in after_block.predecessors


def test_for_else_break_skips_else_clause():
    code = (
        "for item in items:\n"     # 1
        "    if item:\n"           # 2
        "        break\n"          # 3
        "    use(item)\n"          # 4
        "else:\n"                  # 5
        "    done = True\n"        # 6
        "after_break()\n"          # 7
    )

    cfg = build(code)["<module>"]
    break_block = block_containing(cfg, 3)
    else_block = block_containing(cfg, 6)
    after_block = block_containing(cfg, 7)

    # break exits the loop directly into the after-loop block.
    assert after_block in break_block.successors

    # break must NOT enter the else clause.
    assert else_block not in break_block.successors

    # Normal exhaustion still routes through the else clause.
    assert after_block in else_block.successors


def test_while_else_normal_completion_executes_else_clause():
    code = (
        "while cond():\n"          # 1
        "    step()\n"             # 2
        "else:\n"                  # 3
        "    done = True\n"        # 4
        "report(done)\n"           # 5
    )

    cfg = build(code)["<module>"]
    header = cfg.entry
    body_block = block_containing(cfg, 2)
    else_block = block_containing(cfg, 4)
    after_block = block_containing(cfg, 5)

    assert body_block in header.successors
    assert else_block in header.successors
    assert header in body_block.successors
    assert after_block in else_block.successors


def test_while_else_normal_completion_no_direct_bypass_edge():
    code = (
        "while cond():\n"          # 1
        "    step()\n"             # 2
        "else:\n"                  # 3
        "    done = True\n"        # 4
        "report(done)\n"           # 5
    )

    cfg = build(code)["<module>"]
    header = cfg.entry
    else_block = block_containing(cfg, 4)
    after_block = block_containing(cfg, 5)

    assert after_block in else_block.successors

    # Strict Python semantics: no direct header -> after edge
    # when an else clause exists (see for-else counterpart).
    assert header not in after_block.predecessors


def test_while_else_break_skips_else_clause():
    code = (
        "while cond():\n"          # 1
        "    if bad():\n"          # 2
        "        break\n"          # 3
        "    step()\n"             # 4
        "else:\n"                  # 5
        "    done = True\n"        # 6
        "after_break()\n"          # 7
    )

    cfg = build(code)["<module>"]
    break_block = block_containing(cfg, 3)
    else_block = block_containing(cfg, 6)
    after_block = block_containing(cfg, 7)

    assert after_block in break_block.successors
    assert else_block not in break_block.successors
    assert after_block in else_block.successors


# --------------------------------------------------------------------------
# Loops without an else clause
# --------------------------------------------------------------------------


def test_for_without_else_keeps_direct_header_after_edge():
    code = (
        "for item in items:\n"     # 1
        "    use(item)\n"          # 2
        "after_loop()\n"           # 3
    )

    cfg = build(code)["<module>"]
    header = cfg.entry
    body_block = block_containing(cfg, 2)
    after_block = block_containing(cfg, 3)

    # Without an else clause the direct header -> after edge
    # must remain (normal exhaustion leaves the loop).
    assert after_block in header.successors
    assert header in body_block.successors


def test_while_without_else_keeps_direct_header_after_edge():
    code = (
        "while cond():\n"          # 1
        "    step()\n"             # 2
        "after_loop()\n"           # 3
    )

    cfg = build(code)["<module>"]
    header = cfg.entry
    body_block = block_containing(cfg, 2)
    after_block = block_containing(cfg, 3)

    assert after_block in header.successors
    assert header in body_block.successors


# --------------------------------------------------------------------------
# Nested loops with else
# --------------------------------------------------------------------------


def test_nested_for_else_flows_to_inner_after():
    code = (
        "for a in items:\n"        # 1
        "    for b in a:\n"        # 2
        "        use(b)\n"         # 3
        "    else:\n"              # 4
        "        mark(a)\n"        # 5
        "    gap(a)\n"             # 6
        "done()\n"                 # 7
    )

    cfg = build(code)["<module>"]
    outer_header = cfg.entry
    inner_header = block_containing(cfg, 2)
    inner_else = block_containing(cfg, 5)
    inner_after = block_containing(cfg, 6)
    outer_after = block_containing(cfg, 7)

    # Inner loop exhaustion flows through the inner else clause.
    assert inner_after in inner_else.successors
    assert inner_header not in inner_after.predecessors

    # The outer body resumes after the inner loop and loops back.
    assert outer_header in inner_after.successors

    # The outer loop has no else clause: the direct edge to its
    # after block is correct here.
    assert outer_after in outer_header.successors


# --------------------------------------------------------------------------
# Phase 6.1 audit: loop-else edge cases
# --------------------------------------------------------------------------


def test_while_true_with_else_models_false_branch():
    code = (
        "while True:\n"        # 1
        "    step()\n"         # 2
        "else:\n"              # 3
        "    done = True\n"    # 4
        "after()\n"            # 5
    )

    cfg = build(code)["<module>"]
    header = cfg.entry
    body_block = block_containing(cfg, 2)
    else_block = block_containing(cfg, 4)
    after_block = block_containing(cfg, 5)

    # Fix A still holds: no direct header -> after edge.
    assert header not in after_block.predecessors
    assert after_block in else_block.successors

    # Known limitation, documented: the builder does not
    # evaluate constant conditions, so the false branch (and
    # with it the else clause and the after block) is modeled
    # as reachable even though `while True` never exhausts.
    assert else_block in header.successors
    assert body_block in header.successors


def test_nested_for_break_skips_inner_else():
    code = (
        "for a in items:\n"    # 1
        "    for b in a:\n"    # 2
        "        if b:\n"      # 3
        "            break\n"  # 4
        "        use(b)\n"     # 5
        "    else:\n"          # 6
        "        mark(a)\n"    # 7
        "    check(a)\n"       # 8
        "done()\n"             # 9
    )

    cfg = build(code)["<module>"]
    outer_header = cfg.entry
    inner_header = block_containing(cfg, 2)
    break_block = block_containing(cfg, 4)
    inner_else = block_containing(cfg, 7)
    inner_after = block_containing(cfg, 8)
    outer_after = block_containing(cfg, 9)

    # Inner break exits to the inner after-loop block.
    assert inner_after in break_block.successors
    assert inner_else not in break_block.successors

    # Inner exhaustion still runs the inner else clause.
    assert inner_after in inner_else.successors
    assert inner_header not in inner_after.predecessors

    # The outer loop has no else: direct edge to its after
    # block is correct.
    assert outer_after in outer_header.successors


def test_nested_for_continue_returns_to_inner_header():
    code = (
        "for a in items:\n"       # 1
        "    for b in a:\n"       # 2
        "        if b:\n"         # 3
        "            continue\n"  # 4
        "        use(b)\n"        # 5
        "    else:\n"             # 6
        "        mark(a)\n"       # 7
        "    check(a)\n"          # 8
        "done()\n"                # 9
    )

    cfg = build(code)["<module>"]
    inner_header = block_containing(cfg, 2)
    continue_block = block_containing(cfg, 4)
    inner_else = block_containing(cfg, 7)
    inner_after = block_containing(cfg, 8)

    # continue targets the inner loop header: the next inner
    # iteration still may exhaust normally into the else.
    assert inner_header in continue_block.successors
    assert inner_else not in continue_block.successors
    assert inner_after not in continue_block.successors

    # Normal exhaustion path through the else clause is intact.
    assert inner_after in inner_else.successors
    assert inner_header not in inner_after.predecessors
