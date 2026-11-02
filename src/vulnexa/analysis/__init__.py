
"""
Code analysis package for Vulnexa.

Provides Phase 5 "Advanced Code Understanding" capabilities:

- symbols:   hierarchical symbol tables
- scope:     variable and scope tracking
- hierarchy: class and call relationships
- cfg:       control flow graphs
- dataflow:  reaching definitions and def-use chains
- analyzer:  combined facade over all analyses
- taint:     taint sources, sinks, propagation and findings
"""

from vulnexa.analysis.analyzer import (
    AnalysisResult,
    analyze_file,
    analyze_source,
    print_analysis_summary,
)
from vulnexa.analysis.taint import FunctionTaintResult, analyze_taint


__all__ = [
    "AnalysisResult",
    "FunctionTaintResult",
    "analyze_file",
    "analyze_source",
    "analyze_taint",
    "print_analysis_summary",
]
