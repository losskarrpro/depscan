import json
import tempfile
import os
from pathlib import Path
import pytest
from scanner.utils import (
    detect_project_type,
    read_requirements_txt,
    read_pyproject_toml,
    read_package_json,
    read_package_lock_json,
    parse_version_constraint,
    normalize_version,
    get_all_dependencies,
    write_json_report,
    write_html_report,
    load_config,
    get_logger
)

def test_detect_project_type_python_requirements():
    with tempfile.TemporaryDirectory() as tmpdir:
        req_file = Path(tmpdir) / "requirements.txt"
        req_file.write_text("requests==2.25.1")
        assert detect_project_type(tmpdir) == "python"

def test_detect_project_type_python_pyproject():
    with tempfile.TemporaryDirectory() as tmpdir:
        pyproject_file = Path(tmpdir) / "pyproject.toml"
        pyproject_file.write_text("[tool.poetry]\nname = 'test'")
        assert detect_project_type(tmpdir) == "python"

def test_detect_project_type_node_package_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        package_file = Path(tmpdir) / "package.json"
        package_file.write_text('{"dependencies": {}}')
        assert detect_project_type(tmpdir) == "node"

def test_detect_project_type_node_package_lock():
    with tempfile.TemporaryDirectory() as tmpdir:
        lock_file = Path(tmpdir) / "package-lock.json"
        lock_file.write_text('{"lockfileVersion": 2}')
        assert detect_project_type(tmpdir) == "node"

def test_detect_project_type_unknown():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert detect_project_type(tmpdir) is None

def test_read_requirements_txt():
    content = """requests==2.25.1
flask>=1.1.2
django~=3.2.0
# comment
numpy
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(content)
        f.flush()
        deps = read_requirements_txt(f.name)
        os.unlink(f.name)
    expected = [
        {"name": "requests", "version": "2.25.1"},
        {"name": "flask", "version": "1.1.2"},
        {"name": "django", "version": "3.2.0"},
        {"name": "numpy", "version": ""}
    ]
    assert deps == expected

def test_read_pyproject_toml():
    content = """
[project]
dependencies = [
    "requests==2.25.1",
    "flask>=1.1.2"
]

[tool.poetry.dependencies]
python = "^3.8"
django = "~3.2.0"
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
        f.write(content)
        f.flush()
        deps = read_pyproject_toml(f.name)
        os.unlink(f.name)
    expected = [
        {"name": "requests", "version": "2.25.1"},
        {"name": "flask", "version": "1.1.2"},
        {"name": "django", "version": "3.2.0"}
    ]
    assert deps == expected

def test_read_package_json():
    content = """
{
    "dependencies": {
        "express": "^4.17.1",
        "lodash": "~4.17.21"
    },
    "devDependencies": {
        "jest": "26.6.3"
    }
}
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write(content)
        f.flush()
        deps = read_package_json(f.name)
        os.unlink(f.name)
    expected = [
        {"name": "express", "version": "4.17.1"},
        {"name": "lodash", "version": "4.17.21"},
        {"name": "jest", "version": "26.6.3"}
    ]
    assert deps == expected

def test_read_package_lock_json():
    content = """
{
    "packages": {
        "": {
            "dependencies": {
                "express": "^4.17.1"
            }
        },
        "node_modules/express": {
            "version": "4.17.2"
        },
        "node_modules/lodash": {
            "version": "4.17.21"
        }
    },
    "dependencies": {
        "express": {
            "version": "4.17.2"
        },
        "lodash": {
            "version": "4.17.21"
        }
    }
}
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write(content)
        f.flush()
        deps = read_package_lock_json(f.name)
        os.unlink(f.name)
    expected = [
        {"name": "express", "version": "4.17.2"},
        {"name": "lodash", "version": "4.17.21"}
    ]
    assert deps == expected

def test_parse_version_constraint():
    assert parse_version_constraint("==2.25.1") == "2.25.1"
    assert parse_version_constraint(">=1.1.2") == "1.1.2"
    assert parse_version_constraint("~=3.2.0") == "3.2.0"
    assert parse_version_constraint("^4.17.1") == "4.17.1"
    assert parse_version_constraint("~4.17.21") == "4.17.21"
    assert parse_version_constraint("") == ""
    assert parse_version_constraint("1.0.0") == "1.0.0"

def test_normalize_version():
    assert normalize_version("v2.25.1") == "2.25.1"
    assert normalize_version("2.25.1") == "2.25.1"
    assert normalize_version("") == ""
    assert normalize_version("1.0") == "1.0"
    assert normalize_version("1.0.0-alpha") == "1.0.0-alpha"

def test_get_all_dependencies_python():
    with tempfile.TemporaryDirectory() as tmpdir:
        req_file = Path(tmpdir) / "requirements.txt"
        req_file.write_text("requests==2.25.1\nflask>=1.1.2")
        deps = get_all_dependencies(tmpdir)
        expected = [
            {"name": "requests", "version": "2.25.1"},
            {"name": "flask", "version": "1.1.2"}
        ]
        assert deps == expected

def test_get_all_dependencies_node():
    with tempfile.TemporaryDirectory() as tmpdir:
        package_file = Path(tmpdir) / "package.json"
        package_file.write_text('{"dependencies": {"express": "^4.17.1"}}')
        deps = get_all_dependencies(tmpdir)
        expected = [
            {"name": "express", "version": "4.17.1"}
        ]
        assert deps == expected

def test_get_all_dependencies_no_project():
    with tempfile.TemporaryDirectory() as tmpdir:
        deps = get_all_dependencies(tmpdir)
        assert deps == []

def test_write_json_report():
    data = {"vulnerabilities": [{"id": "CVE-2021-1234", "package": "requests"}]}
    with tempfile.NamedTemporaryFile(mode='r', suffix='.json', delete=False) as f:
        f.close()
        write_json_report(data, f.name)
        with open(f.name, 'r') as rf:
            loaded = json.load(rf)
        os.unlink(f.name)
    assert loaded == data

def test_write_html_report():
    data = {"vulnerabilities": [{"id": "CVE-2021-1234", "package": "requests"}]}
    with tempfile.NamedTemporaryFile(mode='r', suffix='.html', delete=False) as f:
        f.close()
        write_html_report(data, f.name)
        with open(f.name, 'r') as rf:
            content = rf.read()
        os.unlink(f.name)
    assert "CVE-2021-1234" in content
    assert "requests" in content

def test_load_config():
    config_content = """
project:
  name: test
  type: python
output:
  format: json
  file: report.json
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        f.flush()
        config = load_config(f.name)
        os.unlink(f.name)
    assert config["project"]["name"] == "test"
    assert config["project"]["type"] == "python"
    assert config["output"]["format"] == "json"

def test_load_config_default():
    config = load_config()
    assert isinstance(config, dict)

def test_get_logger():
    logger = get_logger("test_logger")
    assert logger.name == "test_logger"
    assert logger.level == 20  # INFO