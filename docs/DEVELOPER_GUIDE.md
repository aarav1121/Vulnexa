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

## 5. Configure the Python Source Path

Vulnexa currently uses a `src/` project layout.

Set `PYTHONPATH` in the active PowerShell session:

```powershell
$env:PYTHONPATH = "src"
```

This allows Python to locate the `vulnexa` package.

Run this command again when opening a new terminal session.

## 6. Run the Scanner

### Scan a single file

```powershell
python -m vulnexa.scanner samples/vulnerable/unsafe_eval.py
```

### Scan a directory

```powershell
python -m vulnexa.scanner samples
```

## 7. Understand the Output

The scanner currently reports:

- Rule ID
- Severity
- Function name
- File path
- Line number
- Finding message
- Total findings

For directory scans, it also reports:

- Python files found
- Python files scanned
- Scanning errors

A finding indicates a potentially unsafe pattern and requires human review.

## 8. Source Code Responsibilities

| File | Responsibility |
|---|---|
| `src/vulnexa/scanner.py` | Scanner entry point and file/directory scanning |
| `src/vulnexa/rules/insecure_functions.py` | AST visitor and current `eval()` rule |
| `src/vulnexa/models/finding.py` | Structured finding data model |

## 9. Development Guidelines

- Preserve the existing working scanner.
- Inspect existing code before making changes.
- Keep security rules separate from scanner orchestration.
- Use structured Finding objects for detections.
- Never execute target application code during static scanning.
- Document new features and security rules.
- Test changes against safe and vulnerable samples.

## 10. Current Development Limitations

- Only direct `eval()` calls are currently detected.
- No automated test suite has been established yet.
- No JSON report exporter is currently implemented.
- No backend or web dashboard is currently implemented.

## 11. Future Development

The planned development stages are documented in `ROADMAP.md`.
