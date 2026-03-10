import logging
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import asdict

from scanner.models import Dependency, Vulnerability

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False) -> None:
    """Configure le logging pour l'application."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def read_file(file_path: Union[str, Path]) -> str:
    """Lit le contenu d'un fichier."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Le fichier {file_path} n'existe pas.")
    return path.read_text(encoding='utf-8')


def write_file(file_path: Union[str, Path], content: str) -> None:
    """Écrit du contenu dans un fichier."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')


def parse_json(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Parse un fichier JSON."""
    content = read_file(file_path)
    try:
        return json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"Erreur de parsing JSON dans {file_path}: {e}")


def parse_yaml(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Parse un fichier YAML."""
    content = read_file(file_path)
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ValueError(f"Erreur de parsing YAML dans {file_path}: {e}")


def validate_dependency(dep: Dependency) -> bool:
    """Valide qu'une dépendance a les champs requis."""
    if not dep.name or not dep.version:
        logger.warning(f"Dépendance invalide: {dep}")
        return False
    return True


def flatten_vulnerabilities(vound_dict: Dict[str, List[Vulnerability]]) -> List[Vulnerability]:
    """Aplatit le dictionnaire de vulnérabilités en une liste unique."""
    vulnerabilities = []
    for deps in fround_dict.values():
        vulnerabilities.extend(deps)
    return vulnerabilities


def calculate_severity_score(vuln: Vulnerability) -> float:
    """Calcule un score de sévérité basé sur la CVSS si disponible."""
    if vuln.severity and vuln.severity.get('score'):
        return vuln.severity['score']
    return 0.0


def sort_vulnerabilities_by_severity(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """Trie les vulnérabilités par score de sévérité décroissant."""
    return sorted(vulns, key=lambda v: calculate_severity_score(v), reverse=True)


def filter_vulnerabilities_by_severity(
    vulns: List[Vulnerability],
    min_score: float = 0.0
) -> List[Vulnerability]:
    """Filtre les vulnérabilités avec un score de sévérité >= min_score."""
    return [v for v in vulns if calculate_severity_score(v) >= min_score]


def dependency_to_dict(dep: Dependency) -> Dict[str, Any]:
    """Convertit un objet Dependency en dictionnaire."""
    return asdict(dep)


def vulnerability_to_dict(vuln: Vulnerability) -> Dict[str, Any]:
    """Convertit un objet Vulnerability en dictionnaire."""
    return asdict(vuln)


def format_dependency_list(deps: List[Dependency]) -> str:
    """Formate une liste de dépendances pour l'affichage."""
    return "\n".join([f"- {dep.name}@{dep.version}" for dep in deps])


def format_vulnerability_list(vulns: List[Vulnerability]) -> str:
    """Formate une liste de vulnérabilités pour l'affichage."""
    lines = []
    for vuln in vulns:
        lines.append(f"- {vuln.id} ({vuln.package.name}@{vuln.package.version})")
        if vuln.summary:
            lines.append(f"  Résumé: {vuln.summary}")
        if vuln.severity:
            lines.append(f"  Sévérité: {vuln.severity}")
    return "\n".join(lines)


def get_project_root() -> Path:
    """Retourne le chemin racine du projet (basé sur la position de ce fichier)."""
    return Path(__file__).parent.parent


def load_config(config_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Charge la configuration depuis un fichier YAML."""
    if config_path is None:
        config_path = get_project_root() / "config.yaml"
    
    if not Path(config_path).exists():
        logger.warning(f"Fichier de configuration non trouvé: {config_path}")
        return {}
    
    return parse_yaml(config_path)


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Fusionne deux dictionnaires (dict2 écrase dict1)."""
    result = dict1.copy()
    result.update(dict2)
    return result