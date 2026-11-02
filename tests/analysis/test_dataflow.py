
import ast

from vulnexa.analysis.dataflow import analyze_function, analyze_tree
from vulnexa.analysis.cfg import build_cfgs


def parse_results(code: str):
    return analyze_tree(ast.parse(code))


def test_def_use_chain_records_usage_lines():
    code = "def f():\n    y = 1\n    print(y)\n"

    results = parse_results(code)
    flow = results["f"]

    # Defined on line 2, used on line 3.
    assert flow.def_use_chains["y"] == {2: {3}}


def test_use_before_definition_detected():
    code = (
        "def f():\n"
        "    print(x)\n"
        "    x = 5\n"
    )

    results = parse_results(code)
    flow = results["f"]

    assert len(flow.use_before_definition) == 1
    assert flow.use_before_definition[0].name == "x"
    assert flow.use_before_definition[0].line_number == 2


def test_parameter_use_is_not_use_before_definition():
    code = "def f(x):\n    y = x + 1\n    return y\n"

    results = parse_results(code)
    flow = results["f"]

    assert flow.use_before_definition == []


def test_branch_definitions_prevent_false_positive():
    code = (
        "def f(cond):\n"
        "    if cond:\n"
        "        a = 1\n"
        "    else:\n"
        "        a = 2\n"
        "    print(a)\n"
    )

    results = parse_results(code)
    flow = results["f"]

    assert flow.use_before_definition == []


def test_loop_carried_definition_resolved_to_fixpoint():
    code = (
        "def f(n):\n"
        "    i = 0\n"
        "    while i < n:\n"
        "        i = i + 1\n"
        "    return i\n"
    )

    results = parse_results(code)
    flow = results["f"]

    assert flow.use_before_definition == []


def test_builtin_read_not_flagged():
    code = "def f():\n    return len([1])\n"

    results = parse_results(code)

    assert results["f"].use_before_definition == []


def test_module_scope_finds_use_before_definition():
    code = (
        "print(x)\n"
        "x = 1\n"
    )

    results = parse_results(code)
    flow = results["<module>"]

    assert len(flow.use_before_definition) == 1
    assert flow.use_before_definition[0].name == "x"


def test_augmented_assignment_counts_as_use_and_def():
    code = "def f():\n    total = 1\n    total += 2\n    return total\n"

    results = parse_results(code)
    flow = results["f"]

    chain = flow.def_use_chains["total"]
    # Line 2 definition used on line 3 (the += reads the old
    # value); the redefinition on line 3 is used on line 4.
    assert chain[2] == {3}
    assert chain[3] == {4}


def test_global_declaration_not_flagged():
    code = (
        "counter = 0\n"
        "\n"
        "def bump():\n"
        "    global counter\n"
        "    print(counter)\n"
    )

    results = parse_results(code)

    assert results["bump"].use_before_definition == []


def test_get_definitions_returns_variable_definitions():
    code = "def f():\n    a = 1\n    a = 2\n    return a\n"

    results = parse_results(code)
    flow = results["f"]

    definitions = flow.get_definitions("a")

    assert [definition.line_number for definition in definitions] == [2, 3]


# --------------------------------------------------------------------------
# del statement semantics
# --------------------------------------------------------------------------
#
# Intended reaching-definitions semantics: `del x` KILLS the
# reaching definitions of x but does NOT create a new definition.
# Consequences tested below:
# - a use after del (with no other reaching def) is a
#   use-before-definition candidate,
# - the deleted line never appears as a definition site,
# - earlier uses still chain to the original definition.


def test_use_after_del_reported_as_use_before_definition():
    code = (
        "def f():\n"       # 1
        "    x = 1\n"      # 2
        "    del x\n"      # 3
        "    return x\n"   # 4
    )

    results = parse_results(code)
    flow = results["f"]

    flagged = [
        (use.name, use.line_number)
        for use in flow.use_before_definition
    ]

    # After del x there is no live definition of x, so reading
    # it on line 4 must be flagged.
    assert ("x", 4) in flagged


def test_del_does_not_create_a_definition():
    code = (
        "def f():\n"       # 1
        "    x = 1\n"      # 2
        "    print(x)\n"   # 3
        "    del x\n"      # 4
    )

    results = parse_results(code)
    flow = results["f"]

    definition_lines = [
        definition.line_number
        for definition in flow.get_definitions("x")
    ]

    # Only line 2 is a real definition; line 4 deletes.
    assert definition_lines == [2]


def test_use_before_del_chains_to_original_definition():
    code = (
        "def f():\n"       # 1
        "    x = 1\n"      # 2
        "    print(x)\n"   # 3
        "    del x\n"      # 4
    )

    results = parse_results(code)
    flow = results["f"]

    # The use on line 3 chains to the definition on line 2;
    # the del on line 4 must not appear as a def site.
    assert flow.def_use_chains["x"] == {2: {3}}


def test_del_of_one_variable_does_not_affect_others():
    code = (
        "def f():\n"       # 1
        "    x = 1\n"      # 2
        "    y = 2\n"      # 3
        "    del x\n"      # 4
        "    return y\n"   # 5
    )

    results = parse_results(code)
    flow = results["f"]

    # y is untouched by the deletion of x.
    assert flow.def_use_chains["y"] == {3: {5}}
    assert flow.use_before_definition == []


# --------------------------------------------------------------------------
# Loop-else data flow
# --------------------------------------------------------------------------


def test_definitions_from_else_clause_reach_after_loop():
    code = (
        "def f():\n"           # 1
        "    for item in items:\n"  # 2
        "        use(item)\n"  # 3
        "    else:\n"          # 4
        "        done = True\n"  # 5
        "    return done\n"    # 6
    )

    results = parse_results(code)
    flow = results["f"]

    # done is defined in the else clause and used after the
    # loop; on normal exhaustion the else always runs, so the
    # definition reaches the use and nothing is flagged.
    assert flow.use_before_definition == []
    assert flow.def_use_chains["done"] == {5: {6}}


def test_del_followed_by_reassignment_and_use():
    code = (
        "def f():\n"       # 1
        "    x = 1\n"      # 2
        "    del x\n"      # 3
        "    x = 2\n"      # 4
        "    return x\n"   # 5
    )

    results = parse_results(code)
    flow = results["f"]

    # The use after reassignment chains to line 4 only; the
    # del line never appears as a definition site.
    assert flow.def_use_chains["x"] == {4: {5}}
    assert [
        definition.line_number
        for definition in flow.get_definitions("x")
    ] == [2, 4]
    assert flow.use_before_definition == []


def test_del_on_one_branch_retains_definition_on_other():
    code = (
        "def f(c):\n"      # 1
        "    x = 1\n"      # 2
        "    if c:\n"      # 3
        "        del x\n"  # 4
        "    return x\n"   # 5
    )

    results = parse_results(code)
    flow = results["f"]

    # The definition survives on the false branch, so the use
    # is satisfied and nothing is flagged.
    assert flow.def_use_chains["x"] == {2: {5}}
    assert flow.use_before_definition == []


def test_del_on_all_paths_flags_later_use_across_blocks():
    code = (
        "def f(c):\n"      # 1
        "    x = 1\n"      # 2
        "    del x\n"      # 3
        "    if c:\n"      # 4
        "        y = 2\n"  # 5
        "    return x\n"   # 6
    )

    results = parse_results(code)
    flow = results["f"]

    # The deletion kills x before the branch, so the use on
    # line 6 is definitely undefined: no definition reaches it
    # across the block boundary.
    flagged = [
        (use.name, use.line_number)
        for use in flow.use_before_definition
    ]
    assert ("x", 6) in flagged
    assert flow.def_use_chains.get("x", {}) == {}


def test_function_parameter_deleted_then_used():
    code = (
        "def f(x):\n"      # 1
        "    del x\n"      # 2
        "    return x\n"   # 3
    )

    results = parse_results(code)
    flow = results["f"]

    flagged = [
        (use.name, use.line_number)
        for use in flow.use_before_definition
    ]
    assert ("x", 3) in flagged
    assert flow.def_use_chains.get("x", {}) == {}


def test_multiple_deletes_kill_all_targets():
    code = (
        "def f():\n"       # 1
        "    x = 1\n"      # 2
        "    y = 2\n"      # 3
        "    del x, y\n"   # 4
        "    return x\n"   # 5
    )

    results = parse_results(code)
    flow = results["f"]

    flagged = [
        (use.name, use.line_number)
        for use in flow.use_before_definition
    ]
    assert ("x", 5) in flagged

    # The del line is not a definition site for either name.
    assert [
        definition.line_number
        for definition in flow.get_definitions("x")
    ] == [2]
    assert [
        definition.line_number
        for definition in flow.get_definitions("y")
    ] == [3]


def test_delete_only_name_is_not_treated_as_local():
    code = (
        "def f():\n"       # 1
        "    del x\n"      # 2
        "    return x\n"   # 3
    )

    results = parse_results(code)
    flow = results["f"]

    # del does not bind a name: x is not a local variable, so
    # the read resolves to the enclosing (module) scope instead
    # of being flagged as a local use-before-definition.
    assert "x" not in flow.definitions
    assert flow.use_before_definition == []


# --------------------------------------------------------------------------
# Phase 6.1 audit: definition/deletion ordering
# --------------------------------------------------------------------------


def test_multiple_assignments_then_del_in_one_block():
    code = (
        "def f():\n"       # 1
        "    x = 1\n"      # 2
        "    x = 2\n"      # 3
        "    del x\n"      # 4
        "    return x\n"   # 5
    )

    results = parse_results(code)
    flow = results["f"]

    # Both assignments are real definitions; the del kills the
    # surviving one (line 3) before the use.
    assert [
        definition.line_number
        for definition in flow.get_definitions("x")
    ] == [2, 3]

    flagged = [
        (use.name, use.line_number)
        for use in flow.use_before_definition
    ]
    assert ("x", 5) in flagged
    assert flow.def_use_chains.get("x", {}) == {}


def test_multi_target_del_flags_uses_of_all_names():
    code = (
        "def f():\n"        # 1
        "    x = 1\n"       # 2
        "    y = 2\n"       # 3
        "    del x, y\n"    # 4
        "    return x, y\n" # 5
    )

    results = parse_results(code)
    flow = results["f"]

    flagged = [
        (use.name, use.line_number)
        for use in flow.use_before_definition
    ]

    # Every deleted target is dead for later uses.
    assert ("x", 5) in flagged
    assert ("y", 5) in flagged
    assert flow.def_use_chains.get("x", {}) == {}
    assert flow.def_use_chains.get("y", {}) == {}


# --------------------------------------------------------------------------
# Phase 6.1 audit: branch behaviour
# --------------------------------------------------------------------------


def test_def_on_one_branch_del_on_other():
    code = (
        "def f(c):\n"       # 1
        "    if c:\n"       # 2
        "        x = 1\n"   # 3
        "    else:\n"       # 4
        "        del x\n"   # 5
        "    return x\n"    # 6
    )

    results = parse_results(code)
    flow = results["f"]

    # May-analysis contract: the then-branch definition reaches
    # the use, so nothing is flagged. The del branch contributes
    # no definitions.
    assert flow.use_before_definition == []
    assert [
        definition.line_number
        for definition in flow.get_definitions("x")
    ] == [3]
    assert flow.def_use_chains["x"] == {3: {6}}


def test_del_on_one_branch_reassignment_on_other():
    code = (
        "def f(c):\n"       # 1
        "    x = 1\n"       # 2
        "    if c:\n"       # 3
        "        del x\n"   # 4
        "    else:\n"       # 5
        "        x = 2\n"   # 6
        "    return x\n"    # 7
    )

    results = parse_results(code)
    flow = results["f"]

    # The killed x@2 reaches nothing; the use chains only to the
    # else-branch reassignment.
    assert flow.use_before_definition == []
    assert flow.def_use_chains["x"] == {6: {7}}
    assert [
        definition.line_number
        for definition in flow.get_definitions("x")
    ] == [2, 6]


def test_del_on_both_branches_flags_use_at_join():
    code = (
        "def f(c):\n"       # 1
        "    x = 1\n"       # 2
        "    if c:\n"       # 3
        "        del x\n"   # 4
        "    else:\n"       # 5
        "        del x\n"   # 6
        "    return x\n"    # 7
    )

    results = parse_results(code)
    flow = results["f"]

    # Both branch paths delete x, so no definition reaches the
    # use at the merge point.
    flagged = [
        (use.name, use.line_number)
        for use in flow.use_before_definition
    ]
    assert ("x", 7) in flagged
    assert flow.def_use_chains.get("x", {}) == {}
    assert [
        definition.line_number
        for definition in flow.get_definitions("x")
    ] == [2]


def test_definition_after_branch_merge_satisfies_use():
    code = (
        "def f(c):\n"       # 1
        "    x = 1\n"       # 2
        "    if c:\n"       # 3
        "        del x\n"   # 4
        "    x = 5\n"       # 5
        "    return x\n"    # 6
    )

    results = parse_results(code)
    flow = results["f"]

    # The merge-point reassignment dominates the use: the
    # earlier deletion is irrelevant to it.
    assert flow.use_before_definition == []
    assert flow.def_use_chains["x"] == {5: {6}}
    assert [
        definition.line_number
        for definition in flow.get_definitions("x")
    ] == [2, 5]


# --------------------------------------------------------------------------
# Phase 6.1 audit: module and scope behaviour
# --------------------------------------------------------------------------


def test_module_level_del_then_use_is_flagged():
    code = (
        "x = 1\n"           # 1
        "del x\n"           # 2
        "y = x\n"           # 3
    )

    results = parse_results(code)
    flow = results["<module>"]

    # Module bindings follow the same kill-only rule: the del
    # kills x@1, so the read on line 3 is undefined.
    flagged = [
        (use.name, use.line_number)
        for use in flow.use_before_definition
    ]
    assert ("x", 3) in flagged
    assert [
        definition.line_number
        for definition in flow.get_definitions("x")
    ] == [1]
    assert flow.def_use_chains.get("x", {}) == {}


def test_global_declared_del_does_not_flag_use():
    code = (
        "g = 0\n"           # 1
        "def f():\n"        # 2
        "    global g\n"    # 3
        "    del g\n"       # 4
        "    return g\n"    # 5
    )

    results = parse_results(code)
    flow = results["f"]

    # With `global g`, the name never becomes local, so the
    # read is a global reference and outside the local
    # use-before-definition contract.
    assert flow.use_before_definition == []
    assert "g" not in flow.definitions

    module_flow = results["<module>"]
    assert [
        definition.line_number
        for definition in module_flow.get_definitions("g")
    ] == [1]


def test_nonlocal_declared_del_does_not_flag_use():
    code = (
        "def outer():\n"        # 1
        "    x = 1\n"           # 2
        "    def inner():\n"    # 3
        "        nonlocal x\n"  # 4
        "        del x\n"       # 5
        "        return x\n"    # 6
        "    return inner\n"    # 7
    )

    results = parse_results(code)
    flow = results["outer.inner"]

    # With `nonlocal x`, the name is not local to inner, so the
    # read is an enclosing-scope reference and outside the
    # local use-before-definition contract.
    assert flow.use_before_definition == []
    assert "x" not in flow.definitions


def test_parameter_deleted_then_reassigned():
    code = (
        "def f(x):\n"       # 1
        "    del x\n"       # 2
        "    x = 2\n"       # 3
        "    return x\n"    # 4
    )

    results = parse_results(code)
    flow = results["f"]

    # The parameter binding (line 1) is killed by the del; the
    # later use chains only to the reassignment.
    assert flow.use_before_definition == []
    assert [
        definition.line_number
        for definition in flow.get_definitions("x")
    ] == [1, 3]
    assert flow.def_use_chains["x"] == {3: {4}}
