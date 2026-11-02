
import ast
import os
import argparse
from pathlib import Path

from vulnexa.rules.insecure_functions import InsecureFunctionVisitor


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


def scan_file(file_path):
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

    visitor = InsecureFunctionVisitor()
    visitor.visit(syntax_tree)

    for finding in visitor.findings:
        finding.file_path = str(path)

    return visitor.findings


def scan_directory(directory_path):
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
                file_findings = scan_file(file_path)
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


def main():

    parser = argparse.ArgumentParser(
        description="Vulnexa - Custom Python SAST Scanner"
    )

    parser.add_argument(
        "path",
        help="Path to a Python file or project directory"
    )

    args = parser.parse_args()
    target = Path(args.path)

    print("\n================================")
    print("       VULNEXA SAST SCANNER")
    print("================================\n")

    if target.is_file():

        print("Scan type: Single file\n")

        try:
            findings = scan_file(target)

        except (OSError, UnicodeError, SyntaxError) as error:
            print(f"[ERROR] {error}")
            return 1

        print(f"Scanned file: {target}")
        print_findings(findings)

        print(f"\nTotal findings: {len(findings)}")
        return 0

    elif target.is_dir():

        print("Scan type: Directory")
        print(f"Project: {target}\n")

        try:
            result = scan_directory(target)

        except OSError as error:
            print(f"[ERROR] {error}")
            return 1

        print(f"Python files found: {result['files_found']}")
        print(f"Python files scanned: {result['files_scanned']}")

        print_findings(result["findings"])

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
        print(f"Findings      : {len(result['findings'])}")
        print(f"Errors        : {len(result['errors'])}")

        return 1 if result["errors"] else 0

    else:
        print(f"[ERROR] Path does not exist: {target}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
