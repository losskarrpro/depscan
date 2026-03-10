# depscan - Vulnerability Scanner for Dependencies

## Overview

**depscan** is a security tool that automatically scans project dependencies for known vulnerabilities using the Open Source Vulnerability (OSV) database API. It supports Python and Node.js projects, with an extensible architecture for adding more ecosystems.

## Features

- **Automatic project detection** - Identifies Python (requirements.txt, pyproject.toml) and Node.js (package.json, package-lock.json) projects
- **OSV API integration** - Queries the official OSV database for vulnerability information
- **Multiple output formats** - Console, JSON, HTML, and Markdown reports
- **Docker support** - Run scans in isolated containers
- **Extensible architecture** - Easy to add support for new package ecosystems
- **Comprehensive testing** - Full test suite with examples

## Installation

### From PyPI (Recommended)

```bash
pip install depscan-tool
```

### From Source

```bash
git clone https://github.com/yourusername/depscan.git
cd depscan
pip install -e .
```

### Using Docker

```bash
docker build -t depscan .
# or use the pre-built image
docker pull yourusername/depscan:latest
```

## Quick Start

Scan a Python project:

```bash
depscan scan /path/to/python-project
```

Scan a Node.js project:

```bash
depscan scan /path/to/node-project --format html
```

Scan current directory with JSON output:

```bash
depscan scan . --format json --output report.json
```

## Usage

### Command Line Interface

```
depscan [OPTIONS] COMMAND [ARGS]...

Commands:
  scan     Scan a project directory for vulnerabilities
  version  Show version information
  config   Manage configuration

Options:
  --help  Show this message and exit.
```

### Scan Command

```
depscan scan [OPTIONS] PATH

Options:
  --format [console|json|html|markdown]
                                  Output format  [default: console]
  --output FILE                   Output file (required for json/html/markdown)
  --severity [low|medium|high|critical]
                                  Minimum severity to report
  --ignore-packages TEXT          Comma-separated list of packages to ignore
  --config FILE                   Configuration file
  --help                          Show this message and exit.
```

### Configuration File

Create a `config.yaml` file in your project or home directory:

```yaml
# config.yaml
severity: medium
ignore_packages:
  - some-package
  - another-package
output_format: json
osv_api_url: https://api.osv.dev/v1
```

## Supported Ecosystems

- **Python**: `requirements.txt`, `pyproject.toml` (Poetry, PDM, Flit)
- **Node.js**: `package.json`, `package-lock.json`

## Project Structure

```
depscan/
├── scanner/                    # Main package
│   ├── __init__.py
│   ├── cli.py                 # Command-line interface
│   ├── core.py                # Core scanning logic
│   ├── detectors.py           # Project type detection
│   ├── osv_client.py          # OSV API client
│   ├── report.py              # Report generation
│   ├── models.py              # Data models
│   └── utils.py               # Utility functions
├── tests/                     # Test suite
├── examples/                  # Example projects
├── templates/                 # Report templates
├── Dockerfile                 # Docker configuration
├── docker-compose.yml         # Docker Compose setup
├── Makefile                   # Development tasks
├── pyproject.toml            # Python project configuration
├── requirements.txt          # Python dependencies
└── config.yaml               # Default configuration
```

## Examples

### Python Project

```bash
# Scan a Python project with requirements.txt
depscan scan examples/python-project

# Generate HTML report
depscan scan examples/python-project --format html --output report.html
```

### Node.js Project

```bash
# Scan a Node.js project
depscan scan examples/node-project --severity high

# Generate JSON report
depscan scan examples/node-project --format json --output vulnerabilities.json
```

### Using Docker

```bash
# Scan local directory with Docker
docker run -v $(pwd):/app depscan scan /app

# Using Docker Compose
docker-compose run scanner scan /app/examples/python-project
```

## Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/yourusername/depscan.git
cd depscan

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with code coverage
pytest --cov=scanner --cov-report=html
```

### Adding Support for New Ecosystems

1. Extend the `ProjectDetector` class in `scanner/detectors.py`
2. Add dependency parsing logic
3. Update the OSV query format in `scanner/osv_client.py`
4. Add tests in `tests/test_detectors.py`

### Running Tests

```bash
# Run all tests
make test

# Run specific test file
pytest tests/test_osv_client.py

# Run with verbose output
pytest -v

# Run with coverage
make coverage
```

## API Reference

### OSV Client

The `OSVClient` class provides methods to query the OSV API:

```python
from scanner.osv_client import OSVClient

client = OSVClient()
vulnerabilities = client.query_vulnerabilities(
    package="requests",
    version="2.28.0",
    ecosystem="PyPI"
)
```

### Report Generation

Generate reports in different formats:

```python
from scanner.report import ReportGenerator

generator = ReportGenerator(vulnerabilities)
# Console output
generator.generate_console()
# JSON output
generator.generate_json("report.json")
# HTML output
generator.generate_html("report.html")
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code follows the project's coding standards and includes appropriate tests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [OSV Database](https://osv.dev/) for providing the vulnerability data
- All contributors and users of the project

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/depscan/issues)
- Documentation: [GitHub Wiki](https://github.com/yourusername/depscan/wiki)
- Email: support@example.com

## Security

If you discover a security vulnerability, please report it responsibly by emailing security@example.com. Do not create public GitHub issues for security vulnerabilities.