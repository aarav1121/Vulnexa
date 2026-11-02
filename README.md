# Vulnexa

**Vulnexa** is a custom Static Application Security Testing (SAST) engine built in Python. Its goal is to analyze source code without executing the target application and identify potentially insecure coding patterns.

## Project Status

**Current stage:** Initial scanner implementation

Implemented:
- Python source-file scanning.
- Recursive directory scanning.
- Python AST parsing using the built-in `ast` module.
- Custom AST visitor for detecting direct `eval()` calls.
- Structured security findings using a Finding data model.
- File-level scanning error handling.
- Terminal-based scan output.

Planned:
- Custom security rule engine.
- Symbol and scope analysis.
- Control Flow Graph (CFG).
- Data-flow analysis.
- Taint analysis.
- JSON reporting.
- CLI improvements.
- Backend/API and dashboard.

## How It Works

1. The scanner reads Python source files.
2. Python's AST parser converts source code into an Abstract Syntax Tree.
3. Custom AST visitors inspect relevant nodes.
4. Security rules identify potentially unsafe patterns.
5. Findings are returned and displayed in the terminal.

**Important:** Vulnexa does not execute the scanned application's source code.

## Technology Stack

- Python 3.13+
- Python `ast` module
- Git and GitHub
- pytest (planned)

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
│       ├── models/
│       │   └── finding.py
│       ├── rules/
│       │   └── insecure_functions.py
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

## Current Security Rule

| Rule ID | Description | Severity |
|---|---|---|
| VULN-001 | Direct use of `eval()` | WARNING |

The current implementation detects direct calls to `eval()` represented as Python AST name nodes. It does not yet detect aliases, `builtins.eval()`, or other indirect invocation patterns.

Findings indicate potential security risks and do not independently prove exploitability.

## Security Considerations

- Target source code is parsed statically and is not imported or executed.
- Scanned files should still be treated as untrusted input.
- Vulnexa is an evolving security analysis project; current detection coverage is limited.

## Documentation

Detailed documentation is maintained in the `docs/` directory.

## License

License information will be added in a future milestone.