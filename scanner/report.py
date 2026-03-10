import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

from jinja2 import Environment, FileSystemLoader

from scanner.models import Vulnerability, ScanResult


class ReportGenerator:
    """Générateur de rapports pour les résultats de scan."""

    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialise le générateur de rapports.

        Args:
            output_dir: Répertoire de sortie pour les rapports (par défaut: répertoire courant)
        """
        self.output_dir = output_dir or Path.cwd()
        self.templates_dir = Path(__file__).parent.parent / "templates"
        
    def generate_console_report(self, scan_result: ScanResult) -> None:
        """
        Génère un rapport dans la console.

        Args:
            scan_result: Résultat du scan à reporter
        """
        print("\n" + "=" * 80)
        print("RAPPORT DE SCAN DE VULNÉRABILITÉS")
        print("=" * 80)
        
        print(f"\nProjet: {scan_result.project_name}")
        print(f"Type: {scan_result.project_type}")
        print(f"Date du scan: {scan_result.scan_date}")
        print(f"Fichier analysé: {scan_result.dependency_file}")
        
        if scan_result.dependencies:
            print(f"\nDépendances analysées: {len(scan_result.dependencies)}")
        
        if scan_result.vulnerabilities:
            print(f"\n⚠️  VULNÉRABILITÉS DÉTECTÉES: {len(scan_result.vulnerabilities)}")
            print("-" * 80)
            
            for i, vuln in enumerate(scan_result.vulnerabilities, 1):
                print(f"\n{i}. {vuln.package}@{vuln.version}")
                print(f"   ID: {vuln.vuln_id}")
                print(f"   Score CVSS: {vuln.cvss_score or 'N/A'}")
                print(f"   Sévérité: {vuln.severity or 'N/A'}")
                print(f"   Résumé: {vuln.summary}")
                
                if vuln.affected_versions:
                    print(f"   Versions affectées: {', '.join(vuln.affected_versions[:5])}")
                    if len(vuln.affected_versions) > 5:
                        print(f"   ... et {len(vuln.affected_versions) - 5} autres")
                
                if vuln.references:
                    print(f"   Références: {vuln.references[0]}")
                    for ref in vuln.references[1:3]:
                        print(f"             {ref}")
                    if len(vuln.references) > 3:
                        print(f"             ... et {len(vuln.references) - 3} autres")
        else:
            print(f"\n✅ Aucune vulnérabilité détectée!")
        
        print("\n" + "=" * 80)
        print("SCAN TERMINÉ")
        print("=" * 80)
    
    def generate_json_report(self, scan_result: ScanResult, filename: Optional[str] = None) -> Path:
        """
        Génère un rapport JSON.

        Args:
            scan_result: Résultat du scan à reporter
            filename: Nom du fichier de sortie (optionnel)

        Returns:
            Chemin vers le fichier généré
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"depscan_report_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        # Convertir le scan_result en dict
        report_data = {
            "project_name": scan_result.project_name,
            "project_type": scan_result.project_type,
            "scan_date": scan_result.scan_date.isoformat(),
            "dependency_file": str(scan_result.dependency_file),
            "dependencies_count": len(scan_result.dependencies),
            "vulnerabilities_count": len(scan_result.vulnerabilities),
            "dependencies": [
                {
                    "name": dep.name,
                    "version": dep.version,
                    "package_manager": dep.package_manager
                }
                for dep in scan_result.dependencies
            ],
            "vulnerabilities": [
                {
                    "package": vuln.package,
                    "version": vuln.version,
                    "vuln_id": vuln.vuln_id,
                    "summary": vuln.summary,
                    "severity": vuln.severity,
                    "cvss_score": vuln.cvss_score,
                    "affected_versions": vuln.affected_versions,
                    "references": vuln.references,
                    "details": vuln.details
                }
                for vuln in scan_result.vulnerabilities
            ]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"Rapport JSON généré: {output_path}")
        return output_path
    
    def generate_html_report(self, scan_result: ScanResult, filename: Optional[str] = None) -> Path:
        """
        Génère un rapport HTML.

        Args:
            scan_result: Résultat du scan à reporter
            filename: Nom du fichier de sortie (optionnel)

        Returns:
            Chemin vers le fichier généré
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"depscan_report_{timestamp}.html"
        
        output_path = self.output_dir / filename
        
        # Préparer les données pour le template
        template_data = {
            "project_name": scan_result.project_name,
            "project_type": scan_result.project_type,
            "scan_date": scan_result.scan_date.strftime("%Y-%m-%d %H:%M:%S"),
            "dependency_file": str(scan_result.dependency_file),
            "dependencies_count": len(scan_result.dependencies),
            "vulnerabilities_count": len(scan_result.vulnerabilities),
            "vulnerabilities": scan_result.vulnerabilities,
            "has_vulnerabilities": len(scan_result.vulnerabilities) > 0
        }
        
        # Charger et rendre le template
        if self.templates_dir.exists():
            env = Environment(loader=FileSystemLoader(str(self.templates_dir)))
            template = env.get_template("report.html.j2")
            html_content = template.render(**template_data)
        else:
            # Template par défaut si le fichier n'existe pas
            html_content = self._generate_default_html(template_data)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Rapport HTML généré: {output_path}")
        return output_path
    
    def _generate_default_html(self, data: Dict[str, Any]) -> str:
        """Génère un HTML par défaut si le template n'existe pas."""
        vulnerabilities_html = ""
        if data["vulnerabilities"]:
            for vuln in data["vulnerabilities"]:
                severity_class = "warning" if vuln.severity in ["MEDIUM", "HIGH", "CRITICAL"] else "info"
                vulnerabilities_html += f"""
                <div class="vulnerability {severity_class}">
                    <h3>{vuln.package}@{vuln.version} - {vuln.vuln_id}</h3>
                    <p><strong>Sévérité:</strong> {vuln.severity or 'N/A'} | <strong>Score CVSS:</strong> {vuln.cvss_score or 'N/A'}</p>
                    <p><strong>Résumé:</strong> {vuln.summary}</p>
                    <p><strong>Versions affectées:</strong> {', '.join(vuln.affected_versions[:10])}</p>
                    <p><strong>Références:</strong></p>
                    <ul>
                        {"".join(f'<li><a href="{ref}" target="_blank">{ref}</a></li>' for ref in vuln.references[:5])}
                    </ul>
                </div>
                """
        else:
            vulnerabilities_html = '<div class="success">✅ Aucune vulnérabilité détectée!</div>'
        
        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Scan - {data['project_name']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .summary {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .vulnerability {{ border-left: 4px solid #e74c3c; padding: 15px; margin: 15px 0; background: #fff; border-radius: 0 5px 5px 0; }}
        .vulnerability.warning {{ border-left-color: #f39c12; }}
        .vulnerability.info {{ border-left-color: #3498db; }}
        .success {{ background: #2ecc71; color: white; padding: 15px; border-radius: 5px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; margin-right: 5px; }}
        .badge.critical {{ background: #e74c3c; color: white; }}
        .badge.high {{ background: #e67e22; color: white; }}
        .badge.medium {{ background: #f1c40f; color: black; }}
        .badge.low {{ background: #3498db; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Rapport de Scan de Vulnérabilités</h1>
            <h2>{data['project_name']}</h2>
        </div>
        
        <div class="summary">
            <h3>📋 Résumé du Scan</h3>
            <p><strong>Type de projet:</strong> {data['project_type']}</p>
            <p><strong>Date du scan:</strong> {data['scan_date']}</p>
            <p><strong>Fichier analysé:</strong> {data['dependency_file']}</p>
            <p><strong>Dépendances analysées:</strong> {data['dependencies_count']}</p>
            <p><strong>Vulnérabilités détectées:</strong> {data['vulnerabilities_count']}</p>
        </div>
        
        <h3>🔍 Vulnérabilités Détectées</h3>
        {vulnerabilities_html}
        
        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 12px;">
            <p>Généré par depscan - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""