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

**Status: Planned**

- [ ] Establish a consistent rule interface.
- [ ] Separate rule definitions from AST traversal.
- [ ] Support multiple security rules.
- [ ] Add rule metadata and severity handling.
- [ ] Add rule-level positive and negative test cases.

## Phase 5 — Advanced Code Understanding

**Status: Planned**

- [ ] Symbol analysis.
- [ ] Variable and scope tracking.
- [ ] Function and class relationship analysis.
- [ ] Control Flow Graph (CFG).
- [ ] Data-flow analysis.

## Phase 6 — Taint Analysis

**Status: Planned**

- [ ] Identify potential untrusted input sources.
- [ ] Track data propagation.
- [ ] Identify sensitive execution sinks.
- [ ] Analyze potential source-to-sink paths.
- [ ] Reduce false positives through improved analysis.

## Phase 7 — Reporting

**Status: Planned**

- [ ] Structured JSON reports.
- [ ] Finding aggregation.
- [ ] Severity-based summaries.
- [ ] Scan metadata and statistics.

## Phase 8 — Backend and Scanning Infrastructure

**Status: Planned**

- [ ] Backend/API architecture.
- [ ] Background scan workers.
- [ ] Scan job management.
- [ ] Persistent scan history.
- [ ] Restricted processing of untrusted projects.

## Phase 9 — Web Dashboard

**Status: Planned**

- [ ] Project submission interface.
- [ ] Scan progress.
- [ ] Findings dashboard.
- [ ] Finding details and recommendations.
- [ ] Scan history and report downloads.

## Development Principles

1. Build and validate each component before expanding.
2. Preserve working functionality.
3. Keep security rules modular.
4. Never execute scanned application code.
5. Treat uploaded projects as untrusted input.
6. Document architectural changes.
7. Use Git commits for meaningful milestones.
8. Create version tags for stable releases.
