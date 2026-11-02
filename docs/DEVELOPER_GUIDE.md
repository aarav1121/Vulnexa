# Vulnexa — Developer Guide

## 1. Introduction

This guide explains how to set up, run, and understand the current Vulnexa development environment.

Vulnexa is a custom Python-based SAST engine.

## 2. Prerequisites

- Windows 10 or later
- Python 3.13+
- Git
- Visual Studio Code (recommended)

## 3. Clone the Repository

```powershell
git clone https://github.com/aarav1121/Vulnexa.git
cd Vulnexa
```

## 4. Create a Virtual Environment

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install development dependencies:

```powershell
python -m pip install pytest
```

## 5. Configure the Python Source Path

Vulnexa currently uses a `src/` project layout.

Set `PYTHONPATH` in the active PowerShell session:

```powershell
$env:PYTHONPATH = "src"
```

This allows Python to locate the `vulnexa` package.

Run this command again when opening a new terminal session.

Note: the pytest suite configures the path automatically through
`tests/conftest.py`, so `python -m pytest tests` works without
setting `PYTHONPATH`.

## 6. Run the Scanner

### Scan a single file

```powershell
python -m vulnexa.scanner samples/vulnerable/unsafe_eval.py
```

### Scan a directory

```powershell
python -m vulnexa.scanner samples
```

### List all security rules

```powershell
python -m vulnexa.scanner --list-rules
```

### Filter by severity

```powershell
python -m vulnexa.scanner samples --min-severity HIGH
```

### Run deep code analysis

```powershell
python -m vulnexa.scanner samples/vulnerable/unsafe_patterns.py --analysis
```

The `--analysis` flag prints symbol, scope, class/call, CFG, and
data-flow summaries for the scanned files.

## 7. Understand the Output

The scanner currently reports:

- Rule ID
- Severity
- Function context
- File path
- Line number
- Finding message and fix recommendation

Findings are sorted from most to least severe, followed by a
per-severity count summary.

For directory scans, it also reports:

- Python files found
- Python files scanned
- Scanning errors

A finding indicates a potentially unsafe pattern and requires human review.

## 8. Source Code Responsibilities

| File | Responsibility |
|---|---|
| `src/vulnexa/scanner.py` | Scanner entry point, file/directory scanning, CLI |
| `src/vulnexa/rules/base.py` | `SecurityRule` interface |
| `src/vulnexa/rules/registry.py` | Rule registry |
| `src/vulnexa/rules/engine.py` | RuleVisitor (AST traversal) and RuleEngine |
| `src/vulnexa/rules/insecure_functions.py` | VULN-001 (`eval`), VULN-002 (`exec`) |
| `src/vulnexa/rules/serialization.py` | VULN-003 (pickle) |
| `src/vulnexa/rules/command_execution.py` | VULN-004 (`os.system`) |
| `src/vulnexa/rules/subprocess_shell.py` | VULN-005 (subprocess `shell=True`) |
| `src/vulnexa/rules/__init__.py` | Default rule set and registry factory |
| `src/vulnexa/models/finding.py` | Structured finding data model |
| `src/vulnexa/models/severity.py` | Severity ordering, sorting, filtering |
| `src/vulnexa/analysis/symbols.py` | Hierarchical symbol tables |
| `src/vulnexa/analysis/scope.py` | Scope and variable tracking |
| `src/vulnexa/analysis/hierarchy.py` | Class and call relationships |
| `src/vulnexa/analysis/cfg.py` | Control flow graphs |
| `src/vulnexa/analysis/dataflow.py` | Reaching definitions and def-use chains |
| `src/vulnexa/analysis/analyzer.py` | Combined analysis facade |

## 9. Run the Tests

From the project root:

```powershell
python -m pytest tests
```

With verbose output:

```powershell
python -m pytest tests -v
```

The test suite covers:

- Every rule with positive and negative test cases (`tests/rules/`).
- Rule registry and rule engine behavior.
- Severity model behavior.
- Scanner regression tests against the `samples/` files.
- Every analysis module (`tests/analysis/`).

## 10. Add a New Security Rule

1. Create a module in `src/vulnexa/rules/`.
2. Subclass `SecurityRule` and call `super().__init__()` with the
   rule metadata (rule ID, title, severity, message, recommendation).
3. Implement `matches(node)` using only AST inspection.
4. Add the rule class to `DEFAULT_RULES` in `src/vulnexa/rules/__init__.py`.
5. Add positive and negative test cases under `tests/rules/`.
6. Document the rule in `docs/SECURITY_RULES.md` and update the
   README rule table.

No changes to the scanner or traversal are needed — the rule
engine picks up new rules from the registry automatically.

## 11. Development Guidelines

- Preserve the existing working scanner.
- Inspect existing code before making changes.
- Keep security rules separate from scanner orchestration.
- Use structured Finding objects for detections.
- Never execute target application code during static scanning.
- Document new features and security rules.
- Run the full test suite after changes.

## 12. Current Development Limitations

- Rules detect direct call patterns only (aliases and shadowing
  are not resolved).
- CFG exceptional flow is approximated.
- No JSON report exporter is currently implemented.
- No backend or web dashboard is currently implemented.

## 13. Future Development

The planned development stages are documented in `ROADMAP.md`.
