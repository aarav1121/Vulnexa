# Vulnexa — Development Roadmap

## Project Vision

Build a custom Python-based Static Application Security Testing (SAST) engine capable of analyzing source code and identifying potentially insecure coding patterns through static analysis.

The project will evolve incrementally from a command-line scanner into a more advanced analysis platform.

## Phase 1 — Project Foundation

**Status: Completed**

- [x] Initialize Python project.
- [x] Configure Git and GitHub.
- [x] Establish the `src/` project structure.
- [x] Create the initial scanner entry point.
- [x] Integrate Python's built-in AST parser.

## Phase 2 — Initial Detection Engine

**Status: Completed**

- [x] Implement custom AST visitor.
- [x] Detect direct `eval()` calls.
- [x] Introduce the Finding data model.
- [x] Scan individual Python files.
- [x] Scan directories recursively.
- [x] Handle file-level scanning errors.
- [x] Add safe and vulnerable sample files.

## Phase 3 — Documentation and Project Workflow

**Status: In Progress**

- [x] Maintain project README.
- [x] Document system architecture.
- [x] Document current security rules.
- [x] Create developer setup guide.
- [x] Complete roadmap and changelog.
- [x] Verify scanner regression tests.
- [ ] Establish a stable version milestone.

## Phase 4 — Custom Security Rule Engine

**Status: Completed**

- [x] Establish a consistent rule interface.
- [x] Separate rule definitions from AST traversal.
- [x] Support multiple security rules.
- [x] Add rule metadata and severity handling.
- [x] Implement built-in security rules.
- [x] Add rule-level positive and negative test cases.
- [x] Implement rule registration and lookup.
- [x] Support severity-based sorting, filtering, and counting.

## Phase 5 — Advanced Code Understanding

**Status: Completed**

- [x] Implement hierarchical symbol analysis.
- [x] Implement variable and scope tracking.
- [x] Implement function and class relationship analysis.
- [x] Build Control Flow Graphs (CFG).
- [x] Implement reaching-definitions data-flow analysis.
- [x] Implement def-use chains.
- [x] Add conservative use-before-definition detection.
- [x] Integrate analysis components through a combined analysis facade.
- [x] Add CLI support for deep code analysis.

## Phase 6 — Taint Analysis

**Status: Completed**

- [x] Identify supported untrusted input sources.
- [x] Track tainted data through assignments and expressions.
- [x] Propagate taint through branches and loops.
- [x] Integrate taint tracking with control-flow analysis.
- [x] Identify sensitive code execution sinks.
- [x] Identify shell command execution sinks.
- [x] Identify unsafe deserialization sinks.
- [x] Analyze potential source-to-sink data flows.
- [x] Implement sink-specific sanitizer handling.
- [x] Generate structured taint findings with source and sink details.
- [x] Add automated tests for propagation, sanitization, and sink detection.

**Implemented Taint Detection Rules:**

| Rule ID | Detection | Severity |
|---|---|---|
| TAINT-001 | Tainted input reaching `eval()` or `exec()` | WARNING |
| TAINT-002 | Tainted input reaching `os.system()` or `os.popen()` | HIGH |
| TAINT-003 | Tainted input reaching subprocess calls with `shell=True` | HIGH |
| TAINT-004 | Tainted input reaching `pickle.load()` or `pickle.loads()` | HIGH |

**Current Scope and Limitations:**

- Taint analysis is intraprocedural; cross-function propagation is not implemented.
- Function parameters initially start untainted.
- Closure-variable taint propagation is not implemented.
- Sanitizer support is currently limited to recognized `shlex.quote()` and `shlex.join()` calls.
- Dynamic runtime behavior and unresolved aliases are not fully analyzed.
- Static-analysis findings require contextual review and do not automatically prove exploitability.

## Phase 7 — Reporting

**Status: Planned**

- [ ] Implement structured JSON reports.
- [ ] Aggregate findings from security rules and taint analysis.
- [ ] Generate severity-based summaries.
- [ ] Include scan metadata and statistics.
- [ ] Support report serialization and export.

## Phase 8 — Backend and Scanning Infrastructure

**Status: Planned**

- [ ] Design backend/API architecture.
- [ ] Implement background scan workers.
- [ ] Implement scan job management.
- [ ] Maintain persistent scan history.
- [ ] Implement restricted processing of untrusted projects.
- [ ] Add secure project and scan handling.

## Phase 9 — Web Dashboard

**Status: Planned**

- [ ] Build project submission interface.
- [ ] Display scan progress.
- [ ] Build findings dashboard.
- [ ] Display finding details and recommendations.
- [ ] Implement scan history.
- [ ] Support report downloads.

## Development Principles

1. Build and validate each component before expanding.
2. Preserve working functionality.
3. Keep security rules modular.
4. Never execute scanned application code.
5. Treat uploaded projects as untrusted input.
6. Document architectural changes.
7. Use Git commits for meaningful milestones.
8. Create version tags for stable releases.
