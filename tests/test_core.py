import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

import pytest

from scanner.core import scan_project, process_dependencies
from scanner.detectors import ProjectType
from scanner.models import Dependency, Vulnerability


@pytest.fixture
def mock_dependencies():
    return [
        Dependency(name="requests", version="2.25.1", ecosystem="PyPI"),
        Dependency(name="flask", version="1.1.2", ecosystem="PyPI"),
    ]


@pytest.fixture
def mock_vulnerabilities():
    return [
        Vulnerability(
            id="GHSA-xxxx-xxxx-xxxx",
            summary="Test vulnerability in requests",
            details="Details here",
            severity="HIGH",
            references=["https://example.com"],
            affected_packages=[{"package": {"name": "requests", "ecosystem": "PyPI"}}],
        )
    ]


class TestProcessDependencies:
    def test_process_dependencies_with_vulnerabilities(self, mock_dependencies, mock_vulnerabilities):
        mock_client = Mock()
        mock_client.query_vulnerabilities.return_value = {
            "requests": mock_vulnerabilities,
            "flask": [],
        }

        results = process_dependencies(mock_dependencies, mock_client)

        assert len(results) == 2
        assert results[0].dependency.name == "requests"
        assert len(results[0].vulnerabilities) == 1
        assert results[0].vulnerabilities[0].id == "GHSA-xxxx-xxxx-xxxx"
        assert results[1].dependency.name == "flask"
        assert len(results[1].vulnerabilities) == 0

        mock_client.query_vulnerabilities.assert_called_once_with(mock_dependencies)

    def test_process_dependencies_empty(self):
        mock_client = Mock()
        mock_client.query_vulnerabilities.return_value = {}

        results = process_dependencies([], mock_client)

        assert results == []
        mock_client.query_vulnerabilities.assert_called_once_with([])


class TestScanProject:
    @patch("scanner.core.detect_project_type")
    @patch("scanner.core.extract_dependencies")
    @patch("scanner.core.process_dependencies")
    @patch("scanner.core.generate_report")
    def test_scan_project_success(
        self,
        mock_generate_report,
        mock_process_dependencies,
        mock_extract_dependencies,
        mock_detect_project_type,
        mock_dependencies,
        mock_vulnerabilities,
    ):
        project_path = Path("/fake/path")
        output_path = Path("/fake/output.json")
        report_format = "json"

        mock_detect_project_type.return_value = ProjectType.PYTHON
        mock_extract_dependencies.return_value = mock_dependencies

        mock_result = Mock()
        mock_result.dependency = mock_dependencies[0]
        mock_result.vulnerabilities = mock_vulnerabilities
        mock_process_dependencies.return_value = [mock_result]

        scan_project(project_path, output_path, report_format)

        mock_detect_project_type.assert_called_once_with(project_path)
        mock_extract_dependencies.assert_called_once_with(project_path, ProjectType.PYTHON)
        mock_process_dependencies.assert_called_once()
        mock_generate_report.assert_called_once_with([mock_result], output_path, report_format)

    @patch("scanner.core.detect_project_type")
    def test_scan_project_unsupported_type(self, mock_detect_project_type):
        project_path = Path("/fake/path")
        mock_detect_project_type.return_value = ProjectType.UNKNOWN

        with pytest.raises(ValueError, match="Unsupported project type"):
            scan_project(project_path, Path("/tmp/output.json"), "json")

    @patch("scanner.core.detect_project_type")
    @patch("scanner.core.extract_dependencies")
    def test_scan_project_no_dependencies(self, mock_extract_dependencies, mock_detect_project_type):
        project_path = Path("/fake/path")
        mock_detect_project_type.return_value = ProjectType.PYTHON
        mock_extract_dependencies.return_value = []

        with patch("scanner.core.generate_report") as mock_generate_report:
            scan_project(project_path, Path("/tmp/output.json"), "json")

            mock_generate_report.assert_called_once_with([], Path("/tmp/output.json"), "json")

    @patch("scanner.core.detect_project_type")
    @patch("scanner.core.extract_dependencies")
    @patch("scanner.core.process_dependencies")
    @patch("scanner.core.generate_report")
    def test_scan_project_with_temp_output(
        self,
        mock_generate_report,
        mock_process_dependencies,
        mock_extract_dependencies,
        mock_detect_project_type,
        mock_dependencies,
    ):
        project_path = Path("/fake/path")
        mock_detect_project_type.return_value = ProjectType.PYTHON
        mock_extract_dependencies.return_value = mock_dependencies
        mock_process_dependencies.return_value = []

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.json"
            scan_project(project_path, output_path, "json")

            mock_generate_report.assert_called_once_with([], output_path, "json")

    @patch("scanner.core.detect_project_type")
    @patch("scanner.core.extract_dependencies")
    @patch("scanner.core.process_dependencies")
    def test_scan_project_osv_client_error(
        self,
        mock_process_dependencies,
        mock_extract_dependencies,
        mock_detect_project_type,
        mock_dependencies,
    ):
        project_path = Path("/fake/path")
        mock_detect_project_type.return_value = ProjectType.PYTHON
        mock_extract_dependencies.return_value = mock_dependencies
        mock_process_dependencies.side_effect = Exception("OSV API error")

        with pytest.raises(Exception, match="OSV API error"):
            scan_project(project_path, Path("/tmp/output.json"), "json")