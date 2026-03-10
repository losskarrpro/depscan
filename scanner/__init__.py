"""
depscan - Scanner de vulnérabilités pour dépendances de code
"""

__version__ = "0.1.0"
__author__ = "depscan Team"

from scanner.core import scan_project
from scanner.detectors import detect_project_type
from scanner.osv_client import OSVClient
from scanner.report import generate_report
from scanner.models import Vulnerability, Dependency
from scanner.utils import read_dependencies

__all__ = [
    "scan_project",
    "detect_project_type",
    "OSVClient",
    "generate_report",
    "Vulnerability",
    "Dependency",
    "read_dependencies",
]