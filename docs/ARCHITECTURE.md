# Vulnexa — System Architecture

## 1. Overview

Vulnexa is a custom Python-based Static Application Security Testing (SAST) engine.

The current implementation analyzes Python source code using the built-in AST module and identifies selected potentially insecure function calls.

The scanner does not execute the target application's source code.

## 2. Current Architecture

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
                  v
       InsecureFunctionVisitor
                  |
                  v
          Security Rule Check
                  |
                  v
             Finding Model
                  |
                  v
           Terminal Output
```

## 3. Component Responsibilities

### 3.1 Scanner (`scanner.py`)

The scanner is the entry point of the current implementation.

Responsibilities:

- Accept a file or directory path.
- Read Python source files.
- Parse source code into an AST.
- Invoke the custom AST visitor.
- Collect findings.
- Handle file-level scanning errors.
- Display scan results in the terminal.

### 3.2 AST Parser

Vulnexa uses Python's built-in `ast` module.

The parser converts source code into a tree of syntax nodes. The scanner inspects this tree instead of executing the source code.

### 3.3 Insecure Function Visitor (`rules/insecure_functions.py`)

`InsecureFunctionVisitor` extends `ast.NodeVisitor`.

Current responsibilities:

- Visit function-call nodes (`ast.Call`).
- Identify direct function calls represented by `ast.Name`.
- Detect direct calls to `eval()`.
- Create a structured Finding object.

Current rule:

- `VULN-001`: Use of `eval()`.

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
| function | Detected function name |

The `to_dict()` method converts a Finding object into a dictionary.

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

## 5. Current Detection Flow

For each Python source file:

1. Read the file contents.
2. Parse the source using `ast.parse()`.
3. Create an `InsecureFunctionVisitor`.
4. Visit AST nodes.
5. Check function-call nodes.
6. Generate findings for detected direct `eval()` calls.
7. Return findings to the scanner.

## 6. Security Boundaries

- Target application code is not executed.
- Source files are treated as input to static analysis.
- Findings represent potential risks, not guaranteed exploitable vulnerabilities.
- The current rule has limited detection coverage.

## 7. Current Limitations

The current implementation does not yet detect:

- Aliased calls such as `e = eval; e(user_input)`.
- Calls such as `builtins.eval()`.
- Function-name shadowing.
- Indirect or dynamically resolved function calls.
- Other insecure functions such as `exec()`.

## 8. Planned Architecture Extensions

The following components are planned and are not yet implemented:

1. Custom security rule engine.
2. Symbol and scope analysis.
3. Control Flow Graph (CFG).
4. Data-flow analysis.
5. Taint analysis.
6. Structured JSON reporting.
7. Backend/API.
8. Background scan workers.
9. Web dashboard.

These components will be integrated incrementally while preserving the existing scanner.