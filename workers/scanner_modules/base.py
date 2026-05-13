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
        ...
    
    def _finding(self,issue: str,evidence: str,severity: SeverityLevel,remediation: str = "",score_penalty: int = 0,) -> Finding:
        """
        Construct a Finding dict with a consistent shape.
        All scanners must use this instead of building dicts manually.
        """
        return Finding(
            module_name=self.name,
            issue=issue,
            evidence=evidence,
            severity=severity,
            score_penalty=score_penalty,
            remediation=remediation,
        )
        
    def safe_scan(self, target: str, timeout: int = 10) -> list[Finding]:
        """
        Wraps scan() with a top-level exception handler.
        The orchestrator should always call this instead of scan() directly.
        If scan() raises an unexpected exception, it is caught here and
        returned as a finding rather than crashing the Celery worker.
        """
        try:
            return self.scan(target, timeout)
        except Exception as e:
            return [self._finding(
                issue=f"{self.display_name} scanner crashed",
                evidence=f"{type(e).__name__}: {str(e)}",
                severity="medium",
                remediation="This is a scanner bug, not a site vulnerability. Report it to the dev team.",
                score_penalty=0,
            )]