"""Finding model. A finding is evidence, not a verdict of malice."""
from dataclasses import dataclass, field, asdict

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    rule_id: str
    severity: str
    artifact: str          # artifact name the finding belongs to
    file: str              # path relative to the scanned root (or artifact dir)
    line: int = 0          # 1-based, 0 = file-level
    evidence: str = ""     # short quoted excerpt backing the finding
    message: str = ""
    category: str = "code"  # code | config | dependency | suspicious-instruction
    capabilities: list = field(default_factory=list)  # capabilities this evidences

    def to_dict(self):
        return asdict(self)

    def sort_key(self):
        return (SEVERITY_ORDER.get(self.severity, 99), self.file, self.line)
