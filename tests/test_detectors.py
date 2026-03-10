import pytest
from unittest.mock import mock_open, patch
from scanner.detectors import (
    detect_project_type,
    PythonDetector,
    NodeDetector,
    DependencyFile,
    ProjectType,
)


class TestPythonDetector:
    def test_detect_requirements_txt(self):
        mock_data = "requests==2.25.1\nflask>=1.1.2\n"
        with patch("builtins.open", mock_open(read_data=mock_data)):
            with patch("os.path.exists", return_value=True):
                detector = PythonDetector("/some/path")
                result = detector.detect()
                assert result is True
                assert detector.dependency_file == DependencyFile(
                    file_path="/some/path/requirements.txt",
                    project_type=ProjectType.PYTHON,
                )

    def test_detect_pyproject_toml(self):
        mock_data = """
        [tool.poetry.dependencies]
        python = "^3.8"
        requests = "2.25.1"
        """
        with patch("builtins.open", mock_open(read_data=mock_data)):
            with patch("os.path.exists", side_effect=lambda x: x.endswith("pyproject.toml")):
                detector = PythonDetector("/some/path")
                result = detector.detect()
                assert result is True
                assert detector.dependency_file == DependencyFile(
                    file_path="/some/path/pyproject.toml",
                    project_type=ProjectType.PYTHON,
                )

    def test_detect_no_file(self):
        with patch("os.path.exists", return_value=False):
            detector = PythonDetector("/some/path")
            result = detector.detect()
            assert result is False
            assert detector.dependency_file is None

    def test_parse_requirements_txt(self):
        mock_data = "requests==2.25.1\nflask>=1.1.2\npytest~=6.2.0\n# comment\ndjango\n"
        with patch("builtins.open", mock_open(read_data=mock_data)):
            with patch("os.path.exists", return_value=True):
                detector = PythonDetector("/some/path")
                detector.detect()
                deps = detector.parse()
                assert len(deps) == 4
                assert deps[0] == {"name": "requests", "version": "2.25.1"}
                assert deps[1] == {"name": "flask", "version": "1.1.2"}
                assert deps[2] == {"name": "pytest", "version": "6.2.0"}
                assert deps[3] == {"name": "django", "version": ""}

    def test_parse_pyproject_toml(self):
        mock_data = """
        [tool.poetry.dependencies]
        python = "^3.8"
        requests = "2.25.1"
        flask = { version = ">=1.1.2", optional = true }
        django = "*"
        """
        with patch("builtins.open", mock_open(read_data=mock_data)):
            with patch("os.path.exists", side_effect=lambda x: x.endswith("pyproject.toml")):
                detector = PythonDetector("/some/path")
                detector.detect()
                deps = detector.parse()
                assert len(deps) == 3
                assert {"name": "requests", "version": "2.25.1"} in deps
                assert {"name": "flask", "version": "1.1.2"} in deps
                assert {"name": "django", "version": ""} in deps

    def test_parse_no_dependency_file(self):
        detector = PythonDetector("/some/path")
        detector.dependency_file = None
        deps = detector.parse()
        assert deps == []


class TestNodeDetector:
    def test_detect_package_json(self):
        mock_data = '{"name": "test", "dependencies": {"express": "^4.17.1"}}'
        with patch("builtins.open", mock_open(read_data=mock_data)):
            with patch("os.path.exists", return_value=True):
                detector = NodeDetector("/some/path")
                result = detector.detect()
                assert result is True
                assert detector.dependency_file == DependencyFile(
                    file_path="/some/path/package.json",
                    project_type=ProjectType.NODE,
                )

    def test_detect_no_file(self):
        with patch("os.path.exists", return_value=False):
            detector = NodeDetector("/some/path")
            result = detector.detect()
            assert result is False
            assert detector.dependency_file is None

    def test_parse_package_json(self):
        mock_data = """
        {
            "name": "test",
            "dependencies": {
                "express": "^4.17.1",
                "lodash": "~4.14.0"
            },
            "devDependencies": {
                "jest": "26.6.0"
            }
        }
        """
        with patch("builtins.open", mock_open(read_data=mock_data)):
            with patch("os.path.exists", return_value=True):
                detector = NodeDetector("/some/path")
                detector.detect()
                deps = detector.parse()
                assert len(deps) == 3
                assert {"name": "express", "version": "4.17.1"} in deps
                assert {"name": "lodash", "version": "4.14.0"} in deps
                assert {"name": "jest", "version": "26.6.0"} in deps

    def test_parse_no_dependency_file(self):
        detector = NodeDetector("/some/path")
        detector.dependency_file = None
        deps = detector.parse()
        assert deps == []


def test_detect_project_type_python():
    with patch("os.path.exists", side_effect=lambda x: "requirements.txt" in x or "pyproject.toml" in x):
        result = detect_project_type("/some/path")
        assert result == ProjectType.PYTHON


def test_detect_project_type_node():
    with patch("os.path.exists", side_effect=lambda x: "package.json" in x):
        result = detect_project_type("/some/path")
        assert result == ProjectType.NODE


def test_detect_project_type_unknown():
    with patch("os.path.exists", return_value=False):
        result = detect_project_type("/some/path")
        assert result == ProjectType.UNKNOWN