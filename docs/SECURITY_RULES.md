# Vulnexa — Security Rules

## 1. Purpose

This document describes the security detection rules implemented in Vulnexa.

Each rule identifies a potentially insecure coding pattern in Python source code.

A detection is a security signal and does not automatically prove that a vulnerability is exploitable.

## 2. Rule Identification Format

Every security rule must have:

| Field | Description |
|---|---|
| Rule ID | Unique identifier |
| Title | Short name of the issue |
| Severity | Risk classification |
| Detection Logic | How the pattern is identified |
| Message | Explanation of the issue |
| Recommendation | Suggested remediation |

## 3. Implemented Rules

### VULN-001 — Use of eval()

**Status:** Implemented

**Severity:** WARNING

**Description:**

Python's `eval()` function evaluates a dynamically supplied Python expression.

Using it with untrusted input can allow an attacker to influence the expression being evaluated.

**Detection Logic:**

Vulnexa uses Python AST traversal to inspect `ast.Call` nodes.

The current rule checks whether:

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

## 4. Planned Rules

These rules are candidates for future implementation. They are not currently active.

| Potential Rule | Security Concern |
|---|---|
| `exec()` usage | Dynamic execution of Python code |
| Unsafe deserialization | Potentially dangerous deserialization |
| Command execution | Unsafe operating-system command invocation |
| Hardcoded credentials | Secrets embedded in source code |
| SQL injection patterns | Unsafe SQL query construction |
| Path traversal patterns | Unsafe file path handling |

The detection logic and final rule IDs will be defined when each rule is implemented.

## 5. Severity Classification

The following severity levels are proposed for the future rule engine:

| Severity | Meaning |
|---|---|
| CRITICAL | Potentially severe security impact |
| HIGH | Significant potential security impact |
| MEDIUM | Moderate potential security impact |
| LOW | Limited potential security impact |
| INFO | Informational observation |
| WARNING | Potentially unsafe pattern requiring review |

The current implementation uses `WARNING` for VULN-001.

## 6. Rule Development Principles

Every new rule should:

1. Have a unique rule ID.
2. Include a clear description.
3. Explain the potential security impact.
4. Provide a remediation recommendation.
5. Be tested against relevant positive and negative examples.
6. Avoid executing the scanned source code.
7. Document known limitations and possible false positives.