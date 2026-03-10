import json
import toml
import yaml
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from scanner.models import Dependency, ProjectType

logger = logging.getLogger(__name__)

@dataclass
class DetectionResult:
    project_type: ProjectType
    dependencies: List[Dependency]
    file_path: Path

class BaseDetector:
    """Classe de base pour les détecteurs de dépendances."""
    
    def __init__(self, project_path: Path):
        self.project_path = project_path
    
    def detect(self) -> Optional[DetectionResult]:
        """Détecte si ce détecteur peut analyser le projet et retourne les dépendances."""
        raise NotImplementedError
    
    def _read_file(self, file_path: Path) -> Optional[str]:
        """Lit un fichier et retourne son contenu."""
        try:
            return file_path.read_text(encoding='utf-8')
        except Exception as e:
            logger.debug(f"Impossible de lire le fichier {file_path}: {e}")
            return None

class PythonRequirementsDetector(BaseDetector):
    """Détecteur pour requirements.txt (Python)."""
    
    def detect(self) -> Optional[DetectionResult]:
        requirements_file = self.project_path / 'requirements.txt'
        if not requirements_file.exists():
            return None
        
        content = self._read_file(requirements_file)
        if not content:
            return None
        
        dependencies = self._parse_requirements(content)
        return DetectionResult(
            project_type=ProjectType.PYTHON,
            dependencies=dependencies,
            file_path=requirements_file
        )
    
    def _parse_requirements(self, content: str) -> List[Dependency]:
        """Parse le contenu de requirements.txt."""
        dependencies = []
        
        for line in content.splitlines():
            line = line.strip()
            
            # Ignorer les commentaires et les lignes vides
            if not line or line.startswith('#'):
                continue
            
            # Ignorer les options comme -r, -c, etc.
            if line.startswith('-'):
                continue
            
            # Extraire le nom et la version
            parts = line.split('==', 1)
            if len(parts) == 2:
                name, version = parts[0].strip(), parts[1].strip()
            else:
                # Si pas de version spécifiée, on utilise une version vide
                name, version = line.strip(), ''
            
            # Nettoyer le nom (enlever les espaces et caractères spéciaux)
            name = name.split('[')[0]  # Enlever les extras comme package[extra]
            
            if name:
                dependencies.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem='PyPI'
                ))
        
        return dependencies

class PythonPyprojectDetector(BaseDetector):
    """Détecteur pour pyproject.toml (Python)."""
    
    def detect(self) -> Optional[DetectionResult]:
        pyproject_file = self.project_path / 'pyproject.toml'
        if not pyproject_file.exists():
            return None
        
        content = self._read_file(pyproject_file)
        if not content:
            return None
        
        try:
            data = toml.loads(content)
        except Exception as e:
            logger.debug(f"Impossible de parser le fichier {pyproject_file}: {e}")
            return None
        
        dependencies = self._parse_pyproject(data)
        if not dependencies:
            return None
        
        return DetectionResult(
            project_type=ProjectType.PYTHON,
            dependencies=dependencies,
            file_path=pyproject_file
        )
    
    def _parse_pyproject(self, data: dict) -> List[Dependency]:
        """Parse les dépendances depuis pyproject.toml."""
        dependencies = []
        
        # Chercher dans [project.dependencies]
        project_deps = data.get('project', {}).get('dependencies', [])
        for dep in project_deps:
            parsed = self._parse_python_dep_string(dep)
            if parsed:
                dependencies.append(parsed)
        
        # Chercher dans [tool.poetry.dependencies]
        poetry_deps = data.get('tool', {}).get('poetry', {}).get('dependencies', {})
        for name, spec in poetry_deps.items():
            if name.lower() == 'python':
                continue
            version = ''
            if isinstance(spec, str):
                version = spec
            elif isinstance(spec, dict):
                version = spec.get('version', '')
            dependencies.append(Dependency(
                name=name,
                version=version,
                ecosystem='PyPI'
            ))
        
        return dependencies
    
    def _parse_python_dep_string(self, dep_string: str) -> Optional[Dependency]:
        """Parse une chaîne de dépendance Python (PEP 508)."""
        # Simplification: extraire le nom et la version
        dep_string = dep_string.strip()
        
        # Enlever les extras
        if '[' in dep_string:
            dep_string = dep_string.split('[')[0]
        
        # Séparer le nom et la version
        parts = dep_string.split('==', 1)
        if len(parts) == 2:
            name, version = parts[0].strip(), parts[1].strip()
        else:
            name, version = dep_string.strip(), ''
        
        if name:
            return Dependency(
                name=name,
                version=version,
                ecosystem='PyPI'
            )
        return None

class NodePackageDetector(BaseDetector):
    """Détecteur pour package.json (Node.js)."""
    
    def detect(self) -> Optional[DetectionResult]:
        package_file = self.project_path / 'package.json'
        if not package_file.exists():
            return None
        
        content = self._read_file(package_file)
        if not content:
            return None
        
        try:
            data = json.loads(content)
        except Exception as e:
            logger.debug(f"Impossible de parser le fichier {package_file}: {e}")
            return None
        
        dependencies = self._parse_package_json(data)
        return DetectionResult(
            project_type=ProjectType.NODE,
            dependencies=dependencies,
            file_path=package_file
        )
    
    def _parse_package_json(self, data: dict) -> List[Dependency]:
        """Parse les dépendances depuis package.json."""
        dependencies = []
        
        # Dependencies
        deps = data.get('dependencies', {})
        for name, version in deps.items():
            dependencies.append(Dependency(
                name=name,
                version=version,
                ecosystem='npm'
            ))
        
        # DevDependencies
        dev_deps = data.get('devDependencies', {})
        for name, version in dev_deps.items():
            dependencies.append(Dependency(
                name=name,
                version=version,
                ecosystem='npm'
            ))
        
        return dependencies

class NodePackageLockDetector(BaseDetector):
    """Détecteur pour package-lock.json (Node.js)."""
    
    def detect(self) -> Optional[DetectionResult]:
        lock_file = self.project_path / 'package-lock.json'
        if not lock_file.exists():
            return None
        
        content = self._read_file(lock_file)
        if not content:
            return None
        
        try:
            data = json.loads(content)
        except Exception as e:
            logger.debug(f"Impossible de parser le fichier {lock_file}: {e}")
            return None
        
        dependencies = self._parse_package_lock(data)
        return DetectionResult(
            project_type=ProjectType.NODE,
            dependencies=dependencies,
            file_path=lock_file
        )
    
    def _parse_package_lock(self, data: dict) -> List[Dependency]:
        """Parse les dépendances depuis package-lock.json."""
        dependencies = []
        
        # Version 2+ de package-lock.json
        packages = data.get('packages', {})
        for pkg_path, pkg_info in packages.items():
            if pkg_path == "":
                continue  # C'est le projet racine
            
            name = pkg_path.split('node_modules/')[-1]
            version = pkg_info.get('version', '')
            
            if name and version:
                dependencies.append(Dependency(
                    name=name,
                    version=version,
                    ecosystem='npm'
                ))
        
        # Version 1 de package-lock.json
        if not dependencies:
            deps = data.get('dependencies', {})
            for name, pkg_info in deps.items():
                version = pkg_info.get('version', '')
                if version:
                    dependencies.append(Dependency(
                        name=name,
                        version=version,
                        ecosystem='npm'
                    ))
        
        return dependencies

class DependencyDetector:
    """Orchestrateur des détecteurs de dépendances."""
    
    DETECTORS = [
        PythonRequirementsDetector,
        PythonPyprojectDetector,
        NodePackageDetector,
        NodePackageLockDetector,
    ]
    
    @staticmethod
    def for_project_type(project_type: ProjectType) -> Optional[BaseDetector]:
        """Retourne un détecteur approprié pour le type de projet."""
        # Cette méthode est utilisée par scanner/core.py
        # Pour l'instant, on retourne un détecteur générique qui essaiera tous les détecteurs
        # Une implémentation plus propre serait de mapper ProjectType à une classe spécifique
        return None
    
    @staticmethod
    def extract_dependencies(project_path: Path) -> List[Dependency]:
        """Extrait les dépendances en utilisant tous les détecteurs disponibles."""
        dependencies = []
        seen = set()
        
        for detector_class in DependencyDetector.DETECTORS:
            detector = detector_class(project_path)
            result = detector.detect()
            if result:
                for dep in result.dependencies:
                    key = (dep.name, dep.ecosystem)
                    if key not in seen:
                        seen.add(key)
                        dependencies.append(dep)
        
        return dependencies

def detect_project_type(project_path: Path) -> ProjectType:
    """Détecte le type de projet basé sur les fichiers présents."""
    # Vérifier les fichiers Python
    if (project_path / 'requirements.txt').exists() or (project_path / 'pyproject.toml').exists():
        return ProjectType.PYTHON
    
    # Vérifier les fichiers Node.js
    if (project_path / 'package.json').exists():
        return ProjectType.NODE
    
    # Par défaut, inconnu
    return ProjectType.UNKNOWN