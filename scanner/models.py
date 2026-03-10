from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum


class ProjectType(Enum):
    PYTHON = "python"
    NODE = "node"
    UNKNOWN = "unknown"


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str
    license: Optional[str] = None
    file_path: Optional[str] = None


@dataclass
class Vulnerability:
    id: str
    summary: str
    details: str
    affected: List[Dict[str, Any]]
    references: List[Dict[str, str]]
    severity: str
    cvss_score: Optional[float] = None


@dataclass
class ScanResult:
    project_path: str
    project_type: ProjectType
    dependencies: List[Dependency]
    vulnerabilities: List[Vulnerability]
    summary: Dict[str, Any]


@dataclass
class Project:
    path: str
    type: ProjectType
    dependencies: List[Dependency] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)