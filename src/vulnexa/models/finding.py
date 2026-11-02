
from dataclasses import asdict, dataclass


@dataclass
class Finding:
    """
    Standard data structure for a security finding.
    """

    rule_id: str
    title: str
    severity: str
    file_path: str
    line_number: int
    message: str
    recommendation: str
    function: str

    def to_dict(self):
        """
        Convert the finding into a dictionary.
        Useful for JSON reports and API responses.
        """
        return asdict(self)
