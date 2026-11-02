# Vulnexa — System Architecture

## 1. Overview

Vulnexa is a custom Python-based Static Application Security Testing (SAST) engine.

The implementation analyzes Python source code using the built-in AST module through a pluggable security rule engine, and builds deep code-understanding structures: symbol tables, scope information, class/call relationships, control flow graphs, and data-flow facts.

The scanner does not execute the target application's source code.

## 2. High-Level Architecture

```text
                User
                  |
                  v
          Command Line Interface
                  |
                  v
            scanner.py
                  |
          +-------+-------+
          |               |
          v               v
      Single File     Directory Scan
          |               |
          +-------+-------+
                  |
                  v
          Read Python Source
                  |
                  v
              ast.parse()
                  |
                  v
          Abstract Syntax Tree
                  |
        +---------+---------+
        |                   |
        v                   v
   Rule Engine       Analysis Modules
   (rules/engine.py)  (analysis/)
        |                   |
        v                   v
   Security Findings   Symbols / Scopes /
   (models/finding.py) Hierarchy / CFG /
        |              Data Flow
        v                   |
   Terminal Output ---------+
```

## 3. Component Responsibilities

### 3.1 Scanner (`scanner.py`)

The scanner is the entry point.

Responsibilities:

- Accept a file or directory path.
- Read Python source files.
- Parse source code into an AST.
- Run the Rule Engine over the tree.
- Collect findings and scanning errors.
- Optionally run deep analysis (`--analysis`).
- Display results in the terminal.
- Support `--list-rules` and `--min-severity`.

### 3.2 AST Parser

Vulnexa uses Python's built-in `ast` module.

The parser converts source code into a tree of syntax nodes. Vulnexa inspects this tree instead of executing the source code.

### 3.3 Rule Engine (`rules/`)

The rule engine separates **rule definitions** from **AST traversal**.

| Component | Responsibility |
|---|---|
| `rules/base.py` | `SecurityRule` interface: metadata (`rule_id`, `title`, `severity`, `message`, `recommendation`) plus an abstract `matches(node)` method and a standard `create_finding()` factory |
| `rules/registry.py` | `RuleRegistry`: registers rules by unique ID, supports lookup, removal, iteration |
| `rules/engine.py` | `RuleVisitor` (single AST traversal that checks every node against every rule and tracks the qualified function context) and `RuleEngine` (coordinates a registry and a tree) |
| `rules/__init__.py` | `DEFAULT_RULES` list and `create_default_registry()` factory |

Built-in rule modules:

| Module | Rules |
|---|---|
| `rules/insecure_functions.py` | VULN-001 (`eval()`), VULN-002 (`exec()`) |
| `rules/serialization.py` | VULN-003 (`pickle.load`/`loads`) |
| `rules/command_execution.py` | VULN-004 (`os.system`) |
| `rules/subprocess_shell.py` | VULN-005 (`subprocess.*` with `shell=True`) |

Adding a new rule means: subclass `SecurityRule`, implement `matches()`, and add the class to `DEFAULT_RULES`. No scanner or traversal changes are required.

### 3.4 Finding Model (`models/finding.py`)

The Finding dataclass represents a potential security issue.

Fields:

| Field | Purpose |
|---|---|
| rule_id | Unique security rule identifier |
| title | Finding title |
| severity | Severity level |
| file_path | Source file location |
| line_number | Line containing the call |
| message | Explanation of the issue |
| recommendation | Suggested remediation |
| function | Qualified context (e.g. `<module>`, `Class.method`) |

The `to_dict()` method converts a Finding object into a dictionary.

### 3.5 Severity Model (`models/severity.py`)

Severity levels are ordered from least to most severe:

`INFO < LOW < MEDIUM < WARNING < HIGH < CRITICAL`

Provides:

- `severity_rank()` — numeric rank for comparisons.
- `is_at_least()` / `is_valid_severity()`.
- `filter_by_min_severity()` — used by the `--min-severity` CLI option.
- `sort_findings()` — findings sorted from most to least severe.
- `count_by_severity()` — counts used in the terminal summary.

### 3.6 Analysis Modules (`analysis/`)

Phase 5 deep code understanding. Each module reads only the AST.

| Module | Responsibility |
|---|---|
| `analysis/symbols.py` | Hierarchical `SymbolTable` with one table per scope (module, function, class, lambda, comprehension); records functions, methods, classes, variables, parameters, and imports |
| `analysis/scope.py` | `ScopeInfo` per scope with definitions, references, parameters, and global/nonlocal declarations. Applies Python name-resolution rules (lexical chaining, class-scope invisibility, builtins) to report possibly undefined names and unused local variables |
| `analysis/hierarchy.py` | `ClassInfo` (bases, methods), `FunctionInfo` (calls), call graph, reverse call graph, subclass lookup |
| `analysis/cfg.py` | `ControlFlowGraph` of `BasicBlock` nodes for the module body and every function. Handles if/elif/else, while, for, break/continue, return, raise, try/except/else/finally, with, and match. Loop `else` clauses run on normal exhaustion: when a loop has an `else`, the only non-break route into the after-loop block goes through the `else` block. Exceptional edges are approximated |
| `analysis/dataflow.py` | Reaching definitions solved to a fixpoint over each CFG; def-use chains; conservative use-before-definition detection restricted to locally assigned names. `del x` is modeled as kill-only: it invalidates reaching definitions of `x` without creating a definition |
| `analysis/analyzer.py` | Facade combining all analyses into one `AnalysisResult`; used by the scanner's `--analysis` option |

## 4. Directory Scanning

The scanner recursively searches for Python files using `os.walk()`.

It currently excludes these directories:

- `.git`
- `.venv`
- `venv`
- `env`
- `__pycache__`
- `node_modules`
- `build`
- `dist`

The scanner tracks:

- Python files found.
- Python files successfully scanned.
- Potential security findings.
- Files that could not be scanned.

## 5. Detection Flow

For each Python source file:

1. Read the file contents.
2. Parse the source using `ast.parse()`.
3. Create the default `RuleRegistry` (once per CLI run) and a `RuleEngine`.
4. Traverse the AST once; every registered rule is checked at every node.
5. Generate findings for detected patterns.
6. Sort findings by severity and display them with a summary.
7. If `--analysis` is set, also build and display symbol, scope, hierarchy, CFG, and data-flow summaries.

## 6. Security Boundaries

- Target application code is not executed.
- Source files are treated as input to static analysis.
- Findings represent potential risks, not guaranteed exploitable vulnerabilities.
- The current rules have limited detection coverage.

## 7. Current Limitations

The rule engine does not yet detect:

- Aliased calls such as `e = eval; e(user_input)`.
- Calls resolved through `from x import y` shadowing of dangerous APIs.
- Function-name shadowing.
- Indirect or dynamically resolved function calls.

The analysis modules do not yet model:

- Exceptional control flow precisely (try blocks use approximated edges).
- Dynamically created names (`exec()`, `getattr()`, `from x import *`).
- Flow-sensitive path conditions in match guards.

## 8. Planned Architecture Extensions

The following components are planned and are not yet implemented:

1. Taint analysis (source-to-sink tracking built on data-flow).
2. Structured JSON reporting.
3. Backend/API.
4. Background scan workers.
5. Web dashboard.

These components will be integrated incrementally while preserving the existing scanner.
