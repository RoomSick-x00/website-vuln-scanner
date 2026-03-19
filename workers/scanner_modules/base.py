from typing import TypedDict, Literal
from abc import ABC, abstractmethod

SeverityLevel = Literal["info", "low", "medium", "high", "critical"]

class Finding(TypedDict):
    module_name: str
    issue: str
    evidence: str
    severity: SeverityLevel
    score_penalty: int
    remediation: str
    
class BaseScanner(ABC):
    name: str = ""
    display_name: str = ""
    tier: Literal["passive", "active", "intrusive"] = "passive"
    
    @abstractmethod
    def scan(self, target: str, timeout: int = 10) -> list[Finding]:
        """
        Run the scanner against the target URL.

        Every subclass MUST implement this method.

        target:  fully qualified URL e.g. "https://example.com"
        timeout: seconds before giving up on a network operation
        returns: list of Finding dicts
        """