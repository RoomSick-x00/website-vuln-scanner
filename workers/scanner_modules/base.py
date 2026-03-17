# workers/scanner_modules/base.py

from abc import ABC, abstractmethod
from typing import List, Dict


class BaseScanner(ABC):
    """
    Abstract base class for all vulnerability scanner modules.

    Used for:
    - Enforcing interface
    - Auto-discovery via subclass detection
    """

    module_name: str = ""

    def __init__(self) -> None:
        if not self.module_name:
            raise ValueError(
                f"{self.__class__.__name__} must define a non-empty module_name"
            )

    @abstractmethod
    def scan(self, target: str, timeout: int) -> List[Dict]:
        """
        Execute scan against target.

        Returns:
            List of standardized findings.
        """
        raise NotImplementedError

    @classmethod
    def is_valid_scanner(cls) -> bool:
        """
        Utility method for discovery filtering.
        """
        return cls is not BaseScanner