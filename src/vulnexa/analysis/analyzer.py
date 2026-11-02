
"""
Combined analysis facade for Vulnexa.

Runs every Phase 5 analysis over one Python source file and
returns a single result object:

- Symbol tables        (analysis/symbols.py)
- Scope analysis       (analysis/scope.py)
- Class/call hierarchy (analysis/hierarchy.py)
- Control flow graphs  (analysis/cfg.py)
- Data-flow facts      (analysis/dataflow.py)
- Taint analysis       (analysis/taint.py)

This module only reads the AST; scanned source code is never
executed.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path

from vulnexa.analysis.cfg import ControlFlowGraph, build_cfgs
from vulnexa.analysis.dataflow import DataFlowResult, analyze_tree as analyze_dataflow
from vulnexa.analysis.hierarchy import HierarchyResult, analyze_relationships
from vulnexa.analysis.scope import ScopeAnalysisResult, analyze_scopes
from vulnexa.analysis.symbols import SymbolTable, collect_symbols
from vulnexa.analysis.taint import FunctionTaintResult, analyze_taint


@dataclass
class AnalysisResult:
    """
    All analysis output for one source file.

    Combines Phase 5 code understanding with Phase 7 taint
    analysis results.
    """

    file_path: str
    symbols: SymbolTable = None
    scopes: ScopeAnalysisResult = None
    hierarchy: HierarchyResult = None
    cfgs: dict = field(default_factory=dict)
    dataflow: dict = field(default_factory=dict)
    taint: dict = field(default_factory=dict)


def analyze_source(source: str, file_path: str = "<unknown>") -> AnalysisResult:
    """
    Analyze Python source code provided as a string.
    """

    syntax_tree = ast.parse(source, filename=file_path)

    return AnalysisResult(
        file_path=file_path,
        symbols=collect_symbols(syntax_tree),
        scopes=analyze_scopes(syntax_tree),
        hierarchy=analyze_relationships(syntax_tree),
        cfgs=build_cfgs(syntax_tree),
        dataflow=analyze_dataflow(syntax_tree),
        taint=analyze_taint(syntax_tree, file_path=file_path),
    )


def analyze_file(file_path) -> AnalysisResult:
    """
    Analyze one Python source file from disk.
    """

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Python file not found: {path}"
        )

    source = path.read_text(encoding="utf-8-sig")

    return analyze_source(source, file_path=str(path))


def print_analysis_summary(result: AnalysisResult):
    """
    Display a compact summary of the analysis results.
    """

    all_symbols = result.symbols.flatten()
    functions = [
        symbol for symbol in all_symbols
        if symbol.kind in ("function", "method")
    ]
    classes = [
        symbol for symbol in all_symbols
        if symbol.kind == "class"
    ]

    cfg_blocks = sum(
        cfg.block_count() for cfg in result.cfgs.values()
    )

    print("\nCode analysis:")
    print(f"  Symbols        : {len(all_symbols)}")
    print(f"  Functions      : {len(functions)}")
    print(f"  Classes        : {len(classes)}")
    print(f"  Scopes         : {len(result.scopes.scopes)}")
    print(f"  CFG blocks     : {cfg_blocks}")

    if result.scopes.undefined_references:
        print("  Possibly undefined names:")
        for issue in result.scopes.undefined_references:
            print(
                f"    {issue.scope_qualname}: "
                f"'{issue.name}' line {issue.line_number}"
            )

    if result.scopes.unused_variables:
        print("  Unused local variables:")
        for issue in result.scopes.unused_variables:
            print(
                f"    {issue.scope_qualname}: "
                f"'{issue.name}' line {issue.line_number}"
            )

    for function_name, flow in result.dataflow.items():
        if flow.use_before_definition:
            print(f"  Use before definition in {function_name}:")
            for use_point in flow.use_before_definition:
                print(
                    f"    '{use_point.name}' line {use_point.line_number}"
                )

    taint_findings = sum(
        len(flow.findings) for flow in result.taint.values()
    )

    if taint_findings:
        print(f"  Taint findings : {taint_findings}")
        for function_name, flow in result.taint.items():
            if flow.findings:
                print(
                    f"    Taint findings in {function_name}: "
                    f"{len(flow.findings)}"
                )
