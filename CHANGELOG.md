# Changelog

All notable changes to Vulnexa will be documented in this file.

The project follows a milestone-based versioning approach.

## [Unreleased]

### Added — Phase 4 (Custom Security Rule Engine)

- `SecurityRule` interface (`rules/base.py`) defining a consistent contract for rule metadata and detection logic.
- `RuleRegistry` (`rules/registry.py`) managing rule registration by unique rule ID, with lookup, removal, and membership checks.
- `RuleEngine` and `RuleVisitor` (`rules/engine.py`) separating AST traversal from rule definitions; findings now record the qualified function context (e.g. `Class.method`).
- Built-in security rules:
  - `VULN-001` Use of `eval()` (WARNING).
  - `VULN-002` Use of `exec()` (WARNING).
  - `VULN-003` Unsafe pickle deserialization (HIGH).
  - `VULN-004` OS command execution via `os.system()` (HIGH).
  - `VULN-005` `subprocess` calls with `shell=True` (HIGH).
- Severity model (`models/severity.py`) with ordered levels (INFO, LOW, MEDIUM, WARNING, HIGH, CRITICAL), severity-based sorting, filtering, and counting.
- Scanner CLI options: `--list-rules` and `--min-severity`.
- Additional vulnerable and safe sample files covering implemented security rules.
- Automated pytest suite with rule-level positive and negative test cases, registry, engine, severity, and scanner regression tests.

### Added — Phase 5 (Advanced Code Understanding)

- Symbol analysis (`analysis/symbols.py`): hierarchical symbol tables for module, function, class, comprehension, and lambda scopes.
- Variable and scope tracking (`analysis/scope.py`): records definitions and references per scope with Python name-resolution semantics; reports possibly undefined names and unused local variables.
- Function and class relationship analysis (`analysis/hierarchy.py`): class bases and methods, call graph, reverse call graph, and subclass lookup.
- Control Flow Graph construction (`analysis/cfg.py`): basic blocks and edges for module and function bodies, including branches, loops, break/continue, return, try/except/finally, and match statements.
- Data-flow analysis (`analysis/dataflow.py`): reaching definitions solved to a fixpoint over the CFG, def-use chains, and conservative use-before-definition detection.
- Combined analysis facade (`analysis/analyzer.py`) integrating the code analysis components.
- Scanner CLI option `--analysis` for displaying deep analysis summaries for files and directories.

### Added — Phase 6 (Taint Analysis)

- Taint models (`analysis/taint_models.py`) for sources, sinks, sanitizers, taint facts, and structured findings.
- Taint source detection for supported untrusted inputs, including `input()`, `sys.argv`, `os.environ`, and `sys.stdin`.
- Intraprocedural taint propagation through assignments, expressions, attribute and subscript reads, branches, and loops.
- Control-flow-aware taint propagation using conservative merge and fixpoint behavior.
- Taint sink detection:
  - `TAINT-001`: Tainted data reaching `eval()` or `exec()` (WARNING).
  - `TAINT-002`: Tainted data reaching `os.system()` or `os.popen()` (HIGH).
  - `TAINT-003`: Tainted data reaching subprocess calls with `shell=True` (HIGH).
  - `TAINT-004`: Tainted data reaching `pickle.load()` or `pickle.loads()` (HIGH).
- Sink-specific sanitizer handling for `shlex.quote()` and `shlex.join()` to exempt recognized shell-command flows.
- Structured taint findings containing source and sink information, file path, function context, line numbers, severity, and remediation recommendations.
- Integration of taint analysis into the combined analysis facade (`analysis/analyzer.py`).
- Automated tests covering taint sources, propagation, reassignment, control-flow merging, sanitization, sink matching, and finding serialization.

### Changed

- The scanner now uses the Rule Engine and registry instead of the previous single-purpose AST visitor. The legacy `InsecureFunctionVisitor` was removed; its detection logic lives on as `EvalRule` (`VULN-001`).
- Findings in terminal output are sorted from most to least severe, followed by a severity summary.
- The `function` field of a finding now contains the qualified context of the code (e.g. `<module>` or `Class.method`) instead of the called function's own name.
- Deep analysis now includes taint analysis results through the combined analysis facade.

### Known Limitations

- Security rules primarily detect supported direct call patterns; unresolved aliases and dynamic invocation may not be detected.
- Taint analysis is intraprocedural and does not currently propagate taint across function calls.
- Function parameters start untainted, and closure-variable taint propagation is not implemented.
- Taint analysis supports a limited set of recognized sources, sinks, and sanitizers.
- Sanitizer handling currently recognizes `shlex.quote()` and `shlex.join()` for shell-command sink exemptions; it does not establish that every possible command construction is safe.
- Dynamic runtime behavior, unresolved imports, and arbitrary attribute resolution are not fully analyzed.
- CFG exceptional flow is approximated for try statements.
- Scope analysis cannot resolve dynamically created names through mechanisms such as `exec()`, `getattr()`, and `from x import *`.
- Data-flow use-before-definition is a conservative may-analysis; loop-carried definitions resolve through back edges.
- JSON report generation and finding aggregation are planned for the reporting phase.
- Static-analysis findings are potential security signals and require contextual review; they do not automatically prove exploitability.

## Version History

No stable version has been released yet.

Future releases will be documented here when their milestones are completed and verified.
