# Vulnexa

**Vulnexa** is a custom Static Application Security Testing (SAST) engine built in Python. Its goal is to analyze source code without executing the target application and identify potentially insecure coding patterns.

## Project Status

**Current stage:** Rule engine and advanced code understanding

Implemented:
- Python source-file scanning and recursive directory scanning.
- AST parsing using the built-in `ast` module.
- Modular security rule engine with a pluggable rule interface.
- Five built-in security rules (`eval()`, `exec()`, pickle deserialization, `os.system()`, `subprocess` with `shell=True`).
- Severity classification with sorting, filtering, and summaries.
- Hierarchical symbol tables.
- Variable and scope tracking (undefined names, unused locals).
- Function and class relationship analysis (call graph, inheritance).
- Control Flow Graph (CFG) construction.
- Data-flow analysis (reaching definitions, def-use chains).
- Structured security findings using a Finding data model.
- File-level scanning error handling.
- Terminal-based scan output with optional deep analysis.

Planned:
- Taint analysis.
- JSON reporting.
- Backend/API and dashboard.

## How It Works

1. The scanner reads Python source files.
2. Python's AST parser converts source code into an Abstract Syntax Tree.
3. The rule engine traverses the tree and runs every registered security rule against each node.
4. Deep analysis modules build symbol tables, scope information, call graphs, CFGs, and data-flow facts.
5. Findings are returned, sorted by severity, and displayed in the terminal.

**Important:** Vulnexa never executes the scanned application's source code.

## Technology Stack

- Python 3.13+
- Python `ast` module
- pytest
- Git and GitHub

## Project Structure

```text
Vulnexa/
├── docs/
├── reports/
├── samples/
│   ├── safe/
│   └── vulnerable/
├── src/
│   └── vulnexa/
│       ├── analysis/
│       │   ├── analyzer.py
│       │   ├── cfg.py
│       │   ├── dataflow.py
│       │   ├── hierarchy.py
│       │   ├── scope.py
│       │   └── symbols.py
│       ├── models/
│       │   ├── finding.py
│       │   └── severity.py
│       ├── rules/
│       │   ├── base.py
│       │   ├── command_execution.py
│       │   ├── engine.py
│       │   ├── insecure_functions.py
│       │   ├── registry.py
│       │   ├── serialization.py
│       │   └── subprocess_shell.py
│       └── scanner.py
├── tests/
├── README.md
└── .gitignore
```

## Setup

Clone the repository:

```bash
git clone https://github.com/aarav1121/Vulnexa.git
cd Vulnexa
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the development dependencies:

```powershell
python -m pip install pytest
```

Set the source directory in PowerShell:

```powershell
$env:PYTHONPATH = "src"
```

## Usage

Scan a single Python file:

```powershell
python -m vulnexa.scanner samples/vulnerable/unsafe_eval.py
```

Scan a directory:

```powershell
python -m vulnexa.scanner samples
```

List all registered security rules:

```powershell
python -m vulnexa.scanner --list-rules
```

Only report findings at a given severity or higher:

```powershell
python -m vulnexa.scanner samples --min-severity HIGH
```

Run deep code analysis (symbols, scopes, CFG, data flow):

```powershell
python -m vulnexa.scanner samples/vulnerable/unsafe_patterns.py --analysis
```

Run the test suite:

```powershell
python -m pytest tests
```

## Current Security Rules

| Rule ID | Description | Severity |
|---|---|---|
| VULN-001 | Direct use of `eval()` | WARNING |
| VULN-002 | Direct use of `exec()` | WARNING |
| VULN-003 | Unsafe deserialization with `pickle.load()`/`loads()` | HIGH |
| VULN-004 | OS command execution with `os.system()` | HIGH |
| VULN-005 | `subprocess` call with `shell=True` | HIGH |

The rules detect direct call patterns represented as Python AST nodes. They do not yet detect aliases, `from x import y` shadowing of the same APIs, or other indirect invocation patterns.

Findings indicate potential security risks and do not independently prove exploitability.

## Security Considerations

- Target source code is parsed statically and is not imported or executed.
- Scanned files should still be treated as untrusted input.
- Vulnexa is an evolving security analysis project; current detection coverage is limited.

## Documentation

Detailed documentation is maintained in the `docs/` directory.

## License

License information will be added in a future milestone.
