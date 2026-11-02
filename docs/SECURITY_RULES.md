# Vulnexa — Security Rules

## 1. Purpose

This document describes the security detection rules implemented in Vulnexa.

Each rule identifies a potentially insecure coding pattern or a potentially unsafe data flow in Python source code.

Vulnexa uses two complementary detection approaches:

- **Direct-pattern detection (`VULN` rules):** Identifies specific potentially unsafe function calls and coding patterns.
- **Taint analysis (`TAINT` rules):** Tracks supported untrusted input through code and identifies when tainted data reaches sensitive operations.

A detection is a security signal and does not automatically prove that a vulnerability is exploitable.

## 2. Rule Identification Format

Every security rule must have:

| Field | Description |
|---|---|
| Rule ID | Unique identifier |
| Title | Short name of the issue |
| Severity | Risk classification |
| Detection Logic | How the pattern or data flow is identified |
| Message | Explanation of the issue |
| Recommendation | Suggested remediation |

## 3. Implemented Direct-Pattern Rules (VULN)

These rules identify potentially unsafe function calls based on supported AST patterns.

They do not require the input to be proven tainted.

### VULN-001 — Use of eval()

**Status:** Implemented

**Severity:** WARNING

**Description:**

Python's `eval()` function evaluates a dynamically supplied Python expression.

Using it with untrusted input can allow an attacker to influence the expression being evaluated.

**Detection Logic:**

Vulnexa uses Python AST traversal through the rule engine.

The rule checks whether:

- The node represents a function call.
- The called function is represented by `ast.Name`.
- The function name is exactly `eval`.

**Example — Potentially Unsafe:**

```python
user_input = input("Enter expression: ")
result = eval(user_input)
```

**Recommendation:**

Avoid evaluating untrusted input using `eval()`. Prefer safer alternatives appropriate to the application's requirements.

**Current Limitations:**

The rule does not currently detect:

- Aliased calls, such as `e = eval; e(user_input)`.
- Attribute calls, such as `builtins.eval(user_input)`.
- Function-name shadowing.
- Indirect or dynamically resolved calls.

### VULN-002 — Use of exec()

**Status:** Implemented

**Severity:** WARNING

**Description:**

Python's `exec()` function executes dynamically supplied Python statements.

An attacker who can influence the executed string may gain code execution within the application's process.

**Detection Logic:**

The rule checks whether:

- The node represents a function call.
- The called function is represented by `ast.Name`.
- The function name is exactly `exec`.

**Example — Potentially Unsafe:**

```python
user_code = request.json["code"]
exec(user_code)
```

**Recommendation:**

Avoid executing untrusted input with `exec()`. Restructure the application so dynamic behavior does not require executing strings.

**Current Limitations:**

Same as VULN-001: aliases, attribute calls, and shadowing are not detected.

### VULN-003 — Unsafe deserialization with pickle

**Status:** Implemented

**Severity:** HIGH

**Description:**

`pickle.load()` and `pickle.loads()` can execute arbitrary code during deserialization. The pickle format is not safe against maliciously crafted data.

**Detection Logic:**

The rule checks whether:

- The node represents a function call.
- The called function is an `ast.Attribute` with the attribute name `load` or `loads`.
- The attribute is accessed on the module object `pickle` (for example `pickle.loads(...)`).

**Example — Potentially Unsafe:**

```python
import pickle

data = receive_from_network()
obj = pickle.loads(data)
```

**Recommendation:**

Never deserialize data from an untrusted source with pickle. Use a safe serialization format such as JSON instead.

**Current Limitations:**

- `from pickle import loads` followed by a direct `loads(...)` call is not detected by this direct-pattern rule.
- Other unsafe deserializers (for example `yaml.load` without a safe loader) are not detected yet.

### VULN-004 — OS command execution with os.system()

**Status:** Implemented

**Severity:** HIGH

**Description:**

`os.system()` passes a command string through the operating-system shell. If any part of the string comes from untrusted input, an attacker can inject additional shell commands.

**Detection Logic:**

The rule checks whether:

- The node represents a function call.
- The called function is an `ast.Attribute` with the attribute name `system`.
- The attribute is accessed on the module object `os` (for example `os.system(...)`).

**Example — Potentially Unsafe:**

```python
import os

filename = input("File to list: ")
os.system("cat " + filename)
```

**Recommendation:**

Avoid `os.system()` with untrusted input. Prefer the `subprocess` module with a list of arguments and `shell=False`.

**Current Limitations:**

- `from os import system` followed by a direct `system(...)` call is not detected by this direct-pattern rule.
- `os.popen()` is not detected by this direct-pattern rule. Tainted flows reaching supported `os.popen()` calls are handled separately by TAINT-002.

### VULN-005 — subprocess call with shell=True

**Status:** Implemented

**Severity:** HIGH

**Description:**

Calling a supported `subprocess` function with `shell=True` runs the command through the system shell. Combined with untrusted input, this enables shell injection.

**Detection Logic:**

The rule checks whether:

- The node represents a function call.
- The called function is an `ast.Attribute` on the module object `subprocess` with an attribute name of `run`, `call`, `check_call`, `check_output`, or `Popen`, or a direct `ast.Name` with one of those names.
- A keyword argument passed to the call is `shell=True`.

**Example — Potentially Unsafe:**

```python
import subprocess

host = request.args["host"]
subprocess.run("ping " + host, shell=True)
```

**Recommendation:**

Use `shell=False` (the default) and pass the command as a list of arguments.

**Current Limitations:**

- `shell=True` supplied positionally is not detected.
- A local function named `run`, `call`, or `Popen` with a `shell=True` keyword may also match because of name-based matching.

## 4. Implemented Taint Analysis Rules (TAINT)

Taint analysis tracks supported untrusted input through Python code and identifies potential source-to-sink data flows.

Unlike direct-pattern rules, taint rules require the analyzer to identify tainted data reaching a supported sensitive operation.

### 4.1 Supported Taint Sources

The analyzer recognizes supported untrusted input sources, including:

| Source | Description |
|---|---|
| `input()` | Data entered through standard input |
| `sys.argv` | Command-line arguments |
| `os.environ` | Environment variable values |
| `sys.stdin` | Standard input stream |

The implementation may support additional source models. Source recognition depends on the configured taint models and registry.

### 4.2 Taint Propagation

The analyzer tracks tainted data through supported operations, including:

- Variable assignments and chained assignments.
- Binary expressions and string construction.
- Formatted strings (f-strings).
- String formatting operations such as `%` and `.format()`.
- Attribute and subscript reads.
- Supported augmented assignments and assignment expressions.
- Branches and loops using conservative merge and fixpoint behavior.

Taint findings include information about the source and the sensitive sink.

### 4.3 TAINT-001 — Tainted Data Reaching eval() or exec()

**Status:** Implemented

**Severity:** WARNING

**Description:**

Untrusted input reaching `eval()` or `exec()` may allow an attacker to influence dynamically evaluated Python expressions or executed statements.

**Detection Logic:**

The analyzer checks whether tainted data reaches supported calls to:

- `eval()`
- `exec()`

The finding records the source and sink information when a supported flow is identified.

**Example — Potentially Unsafe:**

```python
user_input = input("Enter expression: ")
result = eval(user_input)
```

**Recommendation:**

Avoid evaluating or executing untrusted input. Use safer parsing or application-specific validation instead.

### 4.4 TAINT-002 — Tainted Data Reaching OS Command Execution

**Status:** Implemented

**Severity:** HIGH

**Description:**

Tainted input reaching shell command execution functions may allow an attacker to influence commands executed by the operating system.

**Detection Logic:**

The analyzer checks supported tainted flows reaching:

- `os.system()`
- `os.popen()`

**Example — Potentially Unsafe:**

```python
import os

filename = input("Enter filename: ")
os.system("cat " + filename)
```

**Recommendation:**

Avoid constructing shell commands using untrusted input. Prefer subprocess argument lists with `shell=False`.

### 4.5 TAINT-003 — Tainted Data Reaching subprocess with shell=True

**Status:** Implemented

**Severity:** HIGH

**Description:**

Tainted data passed to supported subprocess calls with `shell=True` may allow shell command injection.

**Detection Logic:**

The analyzer checks whether:

- The call matches a supported subprocess function.
- The `shell` keyword argument is the literal `True`.
- Tainted data reaches the command input.

Supported subprocess function names include:

- `run`
- `call`
- `check_call`
- `check_output`
- `Popen`

**Example — Potentially Unsafe:**

```python
import subprocess

host = input("Enter host: ")
subprocess.run("ping " + host, shell=True)
```

**Recommendation:**

Use `shell=False` and pass commands as separate arguments. Validate untrusted values according to the application's requirements.

### 4.6 TAINT-004 — Tainted Data Reaching Unsafe Pickle Deserialization

**Status:** Implemented

**Severity:** HIGH

**Description:**

Deserializing tainted data using pickle may expose an application to arbitrary code execution through maliciously crafted serialized objects.

**Detection Logic:**

The analyzer checks supported tainted flows reaching:

- `pickle.load()`
- `pickle.loads()`

**Example — Potentially Unsafe:**

```python
import pickle
import sys

data = sys.stdin.buffer.read()
obj = pickle.loads(data)
```

**Recommendation:**

Do not deserialize untrusted data using pickle. Prefer safer serialization formats such as JSON where appropriate.

## 5. Taint Analysis Sanitizer Handling

Vulnexa currently recognizes limited shell-command sanitizer handling.

| Recognized Function | Supported Purpose |
|---|---|
| `shlex.quote()` | Shell-quoting an individual argument |
| `shlex.join()` | Constructing a shell-quoted command string |

**Important Behavior:**

- Recognized sanitizer handling is specific to shell-command sink detection.
- Sanitization does not automatically remove taint for every sink type.
- A value considered safe for a supported shell-command flow may still be tainted for other sensitive operations.
- This limited handling does not prove that every possible command construction is safe.

## 6. Current Taint Analysis Limitations

The current implementation has the following limitations:

- Analysis is intraprocedural; taint is not propagated across function calls.
- Function parameters initially start untainted.
- Closure-variable taint propagation is not implemented.
- Only supported and registered sources, sinks, and sanitizers are recognized.
- Dynamic runtime behavior and unresolved imports or aliases are not fully analyzed.
- Arbitrary attribute resolution is not fully analyzed.
- Static-analysis findings are potential security signals and require contextual review.

## 7. Planned Rules

These rules are candidates for future implementation. They are not currently active as dedicated direct-pattern rules.

| Potential Rule | Security Concern |
|---|---|
| Unsafe `yaml.load` | Unsafe deserialization without a safe loader |
| Dedicated `os.popen()` direct-pattern rule | Shell command execution |
| Hardcoded credentials | Secrets embedded in source code |
| SQL injection patterns | Unsafe SQL query construction |
| Path traversal patterns | Unsafe file path handling |

Note: Tainted flows reaching supported `os.popen()` calls are already covered by TAINT-002. A dedicated direct-pattern rule for `os.popen()` is still a separate planned improvement.

The detection logic and final rule IDs will be defined when each rule is implemented.

## 8. Severity Classification

Vulnexa uses these severity levels, ordered from least to most severe:

| Severity | Meaning |
|---|---|
| INFO | Informational observation |
| LOW | Limited potential security impact |
| MEDIUM | Moderate potential security impact |
| WARNING | Potentially unsafe pattern requiring review |
| HIGH | Significant potential security impact |
| CRITICAL | Potentially severe security impact |

Severity ranking, filtering, and sorting are implemented in `src/vulnexa/models/severity.py`.

## 9. Rule Development Principles

Every new rule should:

1. Have a unique rule ID.
2. Include a clear description.
3. Explain the potential security impact.
4. Provide a remediation recommendation.
5. Be tested against relevant positive and negative examples.
6. Avoid executing the scanned source code.
7. Document known limitations and possible false positives.
8. Clearly distinguish direct-pattern detection from source-to-sink data-flow detection.
