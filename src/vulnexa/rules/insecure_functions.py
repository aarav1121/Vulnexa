
import ast

from vulnexa.models.finding import Finding


class InsecureFunctionVisitor(ast.NodeVisitor):
    """
    Visits Python AST nodes and detects potentially unsafe
    function calls.
    """

    def __init__(self):
        self.findings = []

    def visit_Call(self, node):

        if isinstance(node.func, ast.Name):

            function_name = node.func.id

            if function_name == "eval":

                finding = Finding(
                    rule_id="VULN-001",
                    title="Use of eval()",
                    severity="WARNING",
                    file_path="",
                    line_number=node.lineno,
                    message=(
                        "eval() can execute dynamically "
                        "supplied Python expressions."
                    ),
                    recommendation=(
                        "Avoid using eval() with untrusted "
                        "input. Use safer alternatives."
                    ),
                    function=function_name
                )

                self.findings.append(finding)

        self.generic_visit(node)
