
import ast
import os
import argparse
from pathlib import Path

from vulnexa.rules import create_default_registry
from vulnexa.rules.engine import RuleEngine
from vulnexa.rules.registry import RuleRegistry
from vulnexa.models.severity import (
    SEVERITY_ORDER,
    count_by_severity,
    filter_by_min_severity,
    sort_findings,
)


EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "build",
    "dist",
}


def scan_file(file_path, registry: RuleRegistry = None):
    """
    Read and statically analyze one Python source file.
    Target code is never executed.
    """

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Python file not found: {path}"
        )

    source_code = path.read_text(encoding="utf-8-sig")

    syntax_tree = ast.parse(
        source_code,
        filename=str(path)
    )

    if registry is None:
        registry = create_default_registry()

    engine = RuleEngine(registry)
    findings = engine.analyze(syntax_tree, file_path=str(path))

    return findings


def scan_directory(directory_path, registry: RuleRegistry = None):
    """
    Recursively scan Python files inside a directory.
    """

    root = Path(directory_path)

    if not root.is_dir():
        raise NotADirectoryError(
            f"Directory not found: {root}"
        )

    findings = []
    errors = []

    files_found = 0
    files_scanned = 0

    for current_dir, directories, filenames in os.walk(root):

        directories[:] = [
            directory
            for directory in directories
            if directory not in EXCLUDED_DIRS
        ]

        for filename in sorted(filenames):

            if not filename.endswith(".py"):
                continue

            file_path = Path(current_dir) / filename
            files_found += 1

            try:
                file_findings = scan_file(file_path, registry=registry)
                findings.extend(file_findings)
                files_scanned += 1

            except (OSError, UnicodeError, SyntaxError) as error:
                errors.append({
                    "file": str(file_path),
                    "message": str(error)
                })

    return {
        "files_found": files_found,
        "files_scanned": files_scanned,
        "findings": findings,
        "errors": errors
    }


def print_findings(findings):
    """
    Display findings ordered from most to least severe.
    """

    findings = sort_findings(findings)

    if not findings:
        print("\n[+] No findings detected.")
        return

    print("\nPotential security findings:\n")

    for finding in findings:

        print(f"[{finding.severity}] {finding.rule_id}")
        print(f"Title    : {finding.title}")
        print(f"Function : {finding.function}")
        print(f"File     : {finding.file_path}")
        print(f"Line     : {finding.line_number}")
        print(f"Message  : {finding.message}")
        print(f"Fix      : {finding.recommendation}")
        print("--------------------------------")


def print_severity_summary(findings):

    counts = count_by_severity(findings)

    print("Findings by severity:")
    for severity, count in counts.items():
        if count:
            print(f"  {severity:<10}: {count}")


def _collect_python_files(root: Path):

    python_files = []

    for current_dir, directories, filenames in os.walk(root):

        directories[:] = [
            directory
            for directory in directories
            if directory not in EXCLUDED_DIRS
        ]

        for filename in sorted(filenames):
            if filename.endswith(".py"):
                python_files.append(Path(current_dir) / filename)

    return python_files


def _print_directory_analysis(root: Path):
    """
    Run deep analysis on every Python file in a directory and
    print one summary block per file.
    """

    from vulnexa.analysis import analyze_file, print_analysis_summary

    for file_path in _collect_python_files(root):
        print(f"\nFile: {file_path}")
        try:
            print_analysis_summary(analyze_file(file_path))
        except (OSError, UnicodeError, SyntaxError) as error:
            print(f"  [ANALYSIS] Could not analyze file: {error}")


def print_rule_list(registry: RuleRegistry):

    print("\nRegistered security rules:\n")

    for rule in sorted(
        registry.get_rules(),
        key=lambda rule: rule.rule_id
    ):
        print(f"{rule.rule_id}  [{rule.severity}]  {rule.title}")
        print(f"  {rule.message}")
        print("--------------------------------")


def main():

    parser = argparse.ArgumentParser(
        description="Vulnexa - Custom Python SAST Scanner"
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to a Python file or project directory"
    )

    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="List all registered security rules and exit"
    )

    parser.add_argument(
        "--min-severity",
        choices=SEVERITY_ORDER,
        default=None,
        help="Only report findings at this severity level or higher"
    )

    parser.add_argument(
        "--analysis",
        action="store_true",
        help="Also run deep code analysis (symbols, scopes, CFG, data flow)"
    )

    args = parser.parse_args()

    registry = create_default_registry()

    print("\n================================")
    print("       VULNEXA SAST SCANNER")
    print("================================\n")

    if args.list_rules:
        print_rule_list(registry)
        return 0

    if not args.path:
        parser.error("the following arguments are required: path")

    if args.min_severity:
        print(f"Minimum severity: {args.min_severity}\n")

    target = Path(args.path)

    if target.is_file():

        print("Scan type: Single file\n")

        try:
            findings = scan_file(target, registry=registry)

        except (OSError, UnicodeError, SyntaxError) as error:
            print(f"[ERROR] {error}")
            return 1

        print(f"Scanned file: {target}")

        if args.min_severity:
            findings = filter_by_min_severity(findings, args.min_severity)

        print_findings(findings)
        print_severity_summary(findings)

        if args.analysis:
            try:
                from vulnexa.analysis import analyze_file, print_analysis_summary

                print_analysis_summary(analyze_file(target))
            except SyntaxError as error:
                print(f"[ANALYSIS] File could not be analyzed: {error}")

        print(f"\nTotal findings: {len(findings)}")
        return 0

    elif target.is_dir():

        print("Scan type: Directory")
        print(f"Project: {target}\n")

        try:
            result = scan_directory(target, registry=registry)

        except OSError as error:
            print(f"[ERROR] {error}")
            return 1

        print(f"Python files found: {result['files_found']}")
        print(f"Python files scanned: {result['files_scanned']}")

        reported = result["findings"]
        if args.min_severity:
            reported = filter_by_min_severity(reported, args.min_severity)

        print_findings(reported)
        print_severity_summary(reported)

        if args.analysis:
            _print_directory_analysis(target)

        if result["errors"]:
            print("\nFiles with scanning errors:\n")

            for error in result["errors"]:
                print(f"[ERROR] {error['file']}")
                print(error["message"])
                print("--------------------------------")

        print("\n================================")
        print("          SCAN SUMMARY")
        print("================================")
        print(f"Files found   : {result['files_found']}")
        print(f"Files scanned : {result['files_scanned']}")
        print(f"Findings      : {len(reported)}")
        print(f"Errors        : {len(result['errors'])}")

        return 1 if result["errors"] else 0

    else:
        print(f"[ERROR] Path does not exist: {target}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
