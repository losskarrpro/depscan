import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from scanner.detectors import detect_project_type, DependencyDetector
from scanner.osv_client import OSVClient
from scanner.models import Dependency, Vulnerability, ScanResult
from scanner.report import ReportGenerator
from scanner.utils import load_config

logger = logging.getLogger(__name__)


class DependencyScanner:
    """Scanner central pour les dépendances."""

    def __init__(self, config_path: Optional[str] = None):
        self.config = load_config(config_path)
        self.osv_client = OSVClient(base_url=self.config.get('osv_api_url', 'https://api.osv.dev/v1'))
        self.report_generator = ReportGenerator(self.config)

    def scan(self, project_path: str, output_format: str = 'json') -> ScanResult:
        """
        Exécute un scan complet sur le projet situé à project_path.

        Args:
            project_path: Chemin vers le répertoire du projet.
            output_format: Format du rapport ('json', 'html', 'console').

        Returns:
            ScanResult: Résultat du scan.
        """
        logger.info(f"Démarrage du scan pour le projet : {project_path}")
        project_path_obj = Path(project_path).resolve()

        if not project_path_obj.is_dir():
            raise ValueError(f"Le chemin {project_path} n'est pas un répertoire valide.")

        # Détection du type de projet
        project_type = detect_project_type(project_path_obj)
        logger.info(f"Type de projet détecté : {project_type}")

        # Sélection du détecteur approprié
        detector = DependencyDetector.for_project_type(project_type)
        if detector is None:
            raise ValueError(f"Aucun détecteur disponible pour le type de projet : {project_type}")

        # Extraction des dépendances
        dependencies = detector.extract_dependencies(project_path_obj)
        logger.info(f"{len(dependencies)} dépendance(s) extraite(s).")

        if not dependencies:
            logger.warning("Aucune dépendance trouvée. Fin du scan.")
            return ScanResult(
                project_path=str(project_path_obj),
                project_type=project_type,
                dependencies=[],
                vulnerabilities=[],
                summary={"total_dependencies": 0, "vulnerable_dependencies": 0, "total_vulnerabilities": 0}
            )

        # Recherche des vulnérabilités via OSV
        vulnerabilities = self._query_vulnerabilities(dependencies)
        logger.info(f"{len(vulnerabilities)} vulnérabilité(s) trouvée(s).")

        # Génération du résumé
        summary = self._generate_summary(dependencies, vulnerabilities)

        result = ScanResult(
            project_path=str(project_path_obj),
            project_type=project_type,
            dependencies=dependencies,
            vulnerabilities=vulnerabilities,
            summary=summary
        )

        # Génération du rapport
        self.report_generator.generate(result, output_format)

        return result

    def _query_vulnerabilities(self, dependencies: List[Dependency]) -> List[Vulnerability]:
        """
        Interroge l'API OSV pour chaque dépendance et retourne les vulnérabilités.

        Args:
            dependencies: Liste des dépendances.

        Returns:
            Liste des vulnérabilités trouvées.
        """
        all_vulnerabilities = []
        for dep in dependencies:
            try:
                vulns = self.osv_client.query_vulnerabilities(dep.package_name, dep.version)
                for vuln_data in vulns:
                    vuln = Vulnerability.from_osv_response(vuln_data, dep.package_name, dep.version)
                    all_vulnerabilities.append(vuln)
            except Exception as e:
                logger.error(f"Erreur lors de la requête pour {dep.package_name} {dep.version}: {e}")
        return all_vulnerabilities

    def _generate_summary(self, dependencies: List[Dependency], vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """
        Génère un résumé statistique du scan.

        Args:
            dependencies: Liste des dépendances.
            vulnerabilities: Liste des vulnérabilités.

        Returns:
            Dictionnaire contenant le résumé.
        """
        vulnerable_packages = {vuln.package_name for vuln in vulnerabilities}
        return {
            "total_dependencies": len(dependencies),
            "vulnerable_dependencies": len(vulnerable_packages),
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": self._count_severities(vulnerabilities)
        }

    def _count_severities(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """
        Compte les vulnérabilités par niveau de sévérité.

        Args:
            vulnerabilities: Liste des vulnérabilités.

        Returns:
            Dictionnaire avec le décompte par sévérité.
        """
        severity_count = {}
        for vuln in vulnerabilities:
            sev = vuln.severity or "UNKNOWN"
            severity_count[sev] = severity_count.get(sev, 0) + 1
        return severity_count

    def scan_multiple(self, project_paths: List[str], output_format: str = 'json') -> List[ScanResult]:
        """
        Exécute un scan sur plusieurs projets.

        Args:
            project_paths: Liste des chemins vers les projets.
            output_format: Format du rapport.

        Returns:
            Liste des résultats de scan.
        """
        results = []
        for path in project_paths:
            try:
                result = self.scan(path, output_format)
                results.append(result)
            except Exception as e:
                logger.error(f"Échec du scan pour {path}: {e}")
        return results