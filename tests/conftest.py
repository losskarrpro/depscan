import pytest
import tempfile
import os
from pathlib import Path
import json
import yaml

from scanner.models import Dependency, Vulnerability, Project
from scanner.detectors import PythonDetector, NodeDetector


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_python_project(temp_dir):
    req_file = temp_dir / "requirements.txt"
    req_file.write_text("requests==2.25.1\nflask==1.1.2\n")
    pyproject_file = temp_dir / "pyproject.toml"
    pyproject_file.write_text("""
[project]
name = "test-project"
version = "0.1.0"
dependencies = [
    "requests>=2.25.0",
    "flask==1.1.2",
]
""")
    return temp_dir


@pytest.fixture
def sample_node_project(temp_dir):
    package_file = temp_dir / "package.json"
    package_file.write_text(json.dumps({
        "name": "test-node-project",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.17.1",
            "lodash": "4.17.21"
        }
    }))
    lock_file = temp_dir / "package-lock.json"
    lock_file.write_text(json.dumps({
        "name": "test-node-project",
        "version": "1.0.0",
        "lockfileVersion": 2,
        "requires": True,
        "packages": {
            "": {
                "name": "test-node-project",
                "version": "1.0.0",
                "dependencies": {
                    "express": "^4.17.1",
                    "lodash": "4.17.21"
                }
            },
            "node_modules/express": {
                "version": "4.17.1",
                "resolved": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
                "integrity": "sha512-test"
            },
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                "integrity": "sha512-test"
            }
        }
    }))
    return temp_dir


@pytest.fixture
def sample_dependencies():
    return [
        Dependency(name="requests", version="2.25.1", ecosystem="PyPI"),
        Dependency(name="flask", version="1.1.2", ecosystem="PyPI"),
        Dependency(name="express", version="4.17.1", ecosystem="npm"),
        Dependency(name="lodash", version="4.17.21", ecosystem="npm")
    ]


@pytest.fixture
def sample_vulnerabilities():
    return [
        Vulnerability(
            id="GHSA-xxxx-xxxx-xxxx",
            summary="Test vulnerability in requests",
            details="Details about the vulnerability",
            affected=[
                {
                    "package": {"ecosystem": "PyPI", "name": "requests"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.25.0"}, {"fixed": "2.26.0"}]}]
                }
            ],
            references=[{"url": "https://example.com"}],
            severity="HIGH"
        ),
        Vulnerability(
            id="GHSA-yyyy-yyyy-yyyy",
            summary="Test vulnerability in express",
            details="Details about the vulnerability",
            affected=[
                {
                    "package": {"ecosystem": "npm", "name": "express"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "4.17.0"}, {"fixed": "4.18.0"}]}]
                }
            ],
            references=[{"url": "https://example.com"}],
            severity="MEDIUM"
        )
    ]


@pytest.fixture
def sample_project():
    return Project(
        name="test-project",
        path=Path("/fake/path"),
        type="python",
        dependencies=[
            Dependency(name="requests", version="2.25.1", ecosystem="PyPI"),
            Dependency(name="flask", version="1.1.2", ecosystem="PyPI")
        ]
    )


@pytest.fixture
def mock_osv_response():
    return {
        "vulns": [
            {
                "id": "GHSA-xxxx-xxxx-xxxx",
                "summary": "Test vulnerability",
                "details": "Details here",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "requests"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.25.0"}, {"fixed": "2.26.0"}]}]
                    }
                ],
                "references": [{"url": "https://example.com"}],
                "severity": "HIGH"
            }
        ]
    }


@pytest.fixture
def config_file(temp_dir):
    config_path = temp_dir / "config.yaml"
    config_data = {
        "osv_api_url": "https://api.osv.dev/v1/query",
        "timeout": 30,
        "report_formats": ["json", "html"],
        "output_dir": "./reports"
    }
    with open(config_path, 'w') as f:
        yaml.dump(config_data, f)
    return config_path


@pytest.fixture
def python_detector():
    return PythonDetector()


@pytest.fixture
def node_detector():
    return NodeDetector()