import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from scanner.report import ReportGenerator, VulnerabilityReport
from scanner.models import Vulnerability, Package


@pytest.fixture
def sample_vulnerabilities():
    vuln1 = Vulnerability(
        id="CVE-2021-12345",
        summary="Test vulnerability 1",
        details="Details about vulnerability 1",
        severity="HIGH",
        affected_packages=[
            Package(name="requests", version="2.25.0", ecosystem="PyPI")
        ],
        references=["https://example.com/vuln1"]
    )
    vuln2 = Vulnerability(
        id="CVE-2021-67890",
        summary="Test vulnerability 2",
        details="Details about vulnerability 2",
        severity="MEDIUM",
        affected_packages=[
            Package(name="flask", version="1.1.2", ecosystem="PyPI")
        ],
        references=["https://example.com/vuln2"]
    )
    return [vuln1, vuln2]


@pytest.fixture
def sample_packages():
    return [
        Package(name="requests", version="2.25.0", ecosystem="PyPI"),
        Package(name="flask", version="1.1.2", ecosystem="PyPI"),
        Package(name="express", version="4.17.1", ecosystem="npm")
    ]


@pytest.fixture
def report_generator():
    return ReportGenerator()


class TestVulnerabilityReport:
    def test_init(self, sample_vulnerabilities, sample_packages):
        report = VulnerabilityReport(
            vulnerabilities=sample_vulnerabilities,
            scanned_packages=sample_packages,
            project_type="python",
            scan_duration=5.2
        )
        
        assert len(report.vulnerabilities) == 2
        assert len(report.scanned_packages) == 3
        assert report.project_type == "python"
        assert report.scan_duration == 5.2
        assert report.total_vulnerabilities == 2
        assert report.high_severity_count == 1
        assert report.medium_severity_count == 1
        assert report.low_severity_count == 0
    
    def test_severity_counts(self):
        vuln_high = Vulnerability(
            id="CVE-2021-11111",
            summary="High",
            details="",
            severity="HIGH",
            affected_packages=[],
            references=[]
        )
        vuln_medium = Vulnerability(
            id="CVE-2021-22222",
            summary="Medium",
            details="",
            severity="MEDIUM",
            affected_packages=[],
            references=[]
        )
        vuln_low = Vulnerability(
            id="CVE-2021-33333",
            summary="Low",
            details="",
            severity="LOW",
            affected_packages=[],
            references=[]
        )
        vuln_critical = Vulnerability(
            id="CVE-2021-44444",
            summary="Critical",
            details="",
            severity="CRITICAL",
            affected_packages=[],
            references=[]
        )
        
        report = VulnerabilityReport(
            vulnerabilities=[vuln_high, vuln_medium, vuln_low, vuln_critical],
            scanned_packages=[],
            project_type="python",
            scan_duration=1.0
        )
        
        assert report.total_vulnerabilities == 4
        assert report.critical_severity_count == 1
        assert report.high_severity_count == 1
        assert report.medium_severity_count == 1
        assert report.low_severity_count == 1
    
    def test_to_dict(self, sample_vulnerabilities, sample_packages):
        report = VulnerabilityReport(
            vulnerabilities=sample_vulnerabilities,
            scanned_packages=sample_packages,
            project_type="python",
            scan_duration=5.2
        )
        
        report_dict = report.to_dict()
        
        assert report_dict["project_type"] == "python"
        assert report_dict["scan_duration"] == 5.2
        assert report_dict["total_vulnerabilities"] == 2
        assert report_dict["high_severity_count"] == 1
        assert report_dict["medium_severity_count"] == 1
        assert len(report_dict["vulnerabilities"]) == 2
        assert len(report_dict["scanned_packages"]) == 3
        
        vuln_dict = report_dict["vulnerabilities"][0]
        assert vuln_dict["id"] == "CVE-2021-12345"
        assert vuln_dict["severity"] == "HIGH"
        
        package_dict = report_dict["scanned_packages"][0]
        assert package_dict["name"] == "requests"
        assert package_dict["version"] == "2.25.0"


class TestReportGenerator:
    def test_generate_json(self, report_generator, sample_vulnerabilities, sample_packages):
        report = VulnerabilityReport(
            vulnerabilities=sample_vulnerabilities,
            scanned_packages=sample_packages,
            project_type="python",
            scan_duration=5.2
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = f.name
        
        try:
            report_generator.generate_json(report, output_path)
            
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            assert data["project_type"] == "python"
            assert data["total_vulnerabilities"] == 2
            assert len(data["vulnerabilities"]) == 2
            assert data["vulnerabilities"][0]["id"] == "CVE-2021-12345"
            
        finally:
            Path(output_path).unlink()
    
    def test_generate_json_default_filename(self, report_generator, sample_vulnerabilities, sample_packages):
        report = VulnerabilityReport(
            vulnerabilities=sample_vulnerabilities,
            scanned_packages=sample_packages,
            project_type="python",
            scan_duration=5.2
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            output_path = output_dir / "vulnerability_report.json"
            
            report_generator.generate_json(report, str(output_dir))
            
            assert output_path.exists()
            
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            assert data["project_type"] == "python"
            assert data["total_vulnerabilities"] == 2
    
    @patch("scanner.report.Environment")
    def test_generate_html(self, mock_env, report_generator, sample_vulnerabilities, sample_packages):
        mock_template = Mock()
        mock_template.render.return_value = "<html>Test Report</html>"
        mock_env_instance = Mock()
        mock_env_instance.get_template.return_value = mock_template
        mock_env.return_value = mock_env_instance
        
        report = VulnerabilityReport(
            vulnerabilities=sample_vulnerabilities,
            scanned_packages=sample_packages,
            project_type="python",
            scan_duration=5.2
        )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
            output_path = f.name
        
        try:
            report_generator.generate_html(report, output_path)
            
            mock_env.assert_called_once()
            mock_env_instance.get_template.assert_called_once_with("report.html.j2")
            mock_template.render.assert_called_once_with(report=report)
            
            with open(output_path, 'r') as f:
                content = f.read()
            
            assert content == "<html>Test Report</html>"
            
        finally:
            Path(output_path).unlink()
    
    @patch("scanner.report.Environment")
    def test_generate_html_default_filename(self, mock_env, report_generator, sample_vulnerabilities, sample_packages):
        mock_template = Mock()
        mock_template.render.return_value = "<html>Test Report</html>"
        mock_env_instance = Mock()
        mock_env_instance.get_template.return_value = mock_template
        mock_env.return_value = mock_env_instance
        
        report = VulnerabilityReport(
            vulnerabilities=sample_vulnerabilities,
            scanned_packages=sample_packages,
            project_type="python",
            scan_duration=5.2
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            output_path = output_dir / "vulnerability_report.html"
            
            report_generator.generate_html(report, str(output_dir))
            
            assert output_path.exists()
            
            with open(output_path, 'r') as f:
                content = f.read()
            
            assert content == "<html>Test Report</html>"
    
    def test_generate_console(self, report_generator, sample_vulnerabilities, sample_packages, capsys):
        report = VulnerabilityReport(
            vulnerabilities=sample_vulnerabilities,
            scanned_packages=sample_packages,
            project_type="python",
            scan_duration=5.2
        )
        
        report_generator.generate_console(report)
        
        captured = capsys.readouterr()
        output = captured.out
        
        assert "Vulnerability Scan Report" in output
        assert "python" in output
        assert "5.20 seconds" in output
        assert "Total vulnerabilities: 2" in output
        assert "HIGH: 1" in output
        assert "MEDIUM: 1" in output
        assert "CVE-2021-12345" in output
        assert "CVE-2021-67890" in output
    
    def test_generate_all_formats(self, report_generator, sample_vulnerabilities, sample_packages):
        report = VulnerabilityReport(
            vulnerabilities=sample_vulnerabilities,
            scanned_packages=sample_packages,
            project_type="python",
            scan_duration=5.2
        )
        
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            
            with patch.object(report_generator, 'generate_json') as mock_json, \
                 patch.object(report_generator, 'generate_html') as mock_html, \
                 patch.object(report_generator, 'generate_console') as mock_console:
                
                report_generator.generate_all(report, str(output_dir))
                
                mock_json.assert_called_once_with(report, str(output_dir))
                mock_html.assert_called_once_with(report, str(output_dir))
                mock_console.assert_called_once_with(report)
    
    def test_generate_with_no_vulnerabilities(self, report_generator, sample_packages, capsys):
        report = VulnerabilityReport(
            vulnerabilities=[],
            scanned_packages=sample_packages,
            project_type="node",
            scan_duration=3.1
        )
        
        report_generator.generate_console(report)
        
        captured = capsys.readouterr()
        output = captured.out
        
        assert "No vulnerabilities found!" in output
        assert "Total vulnerabilities: 0" in output
        assert "Scanned packages: 3" in output