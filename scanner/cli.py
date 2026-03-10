import argparse
import sys
import json
import logging
from pathlib import Path
from typing import Optional

from .core import scan_project
from .report import generate_report
from .detectors import detect_project_type
from .utils import setup_logging, load_config
from .models import ScanResult

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Scan project dependencies for vulnerabilities using OSV API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s .                          # Scan current directory
  %(prog)s /path/to/project           # Scan specific directory
  %(prog)s . --output report.json     # Save results to JSON file
  %(prog)s . --format html            # Generate HTML report
  %(prog)s . --verbose                # Enable verbose output
  %(prog)s . --config config.yaml     # Use custom configuration
        """
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to project directory (default: current directory)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file for scan results (default: stdout)"
    )

    parser.add_argument(
        "-f", "--format",
        choices=["json", "html", "text"],
        default="json",
        help="Output format (default: json)"
    )

    parser.add_argument(
        "-c", "--config",
        help="Path to configuration file"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="none",
        help="Exit with error code if vulnerabilities of specified severity or higher are found"
    )

    parser.add_argument(
        "--include-dev",
        action="store_true",
        help="Include development dependencies in scan"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout for API requests in seconds (default: 30)"
    )

    return parser.parse_args()


def severity_to_level(severity: str) -> int:
    """Convert severity string to numeric level for comparison."""
    severity_levels = {
        "none": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }
    return severity_levels.get(severity.lower(), 0)


def should_fail(scan_result: ScanResult, fail_level: str) -> bool:
    """Determine if scan should fail based on found vulnerabilities."""
    if fail_level == "none":
        return False

    target_level = severity_to_level(fail_level)
    for vuln in scan_result.vulnerabilities:
        if severity_to_level(vuln.severity) >= target_level:
            return True
    return False


def main() -> int:
    """Main entry point for CLI."""
    args = parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level, args.no_color)

    # Load configuration
    config = {}
    if args.config:
        config_path = Path(args.config)
        if config_path.exists():
            config = load_config(config_path)
        else:
            logger.warning(f"Configuration file not found: {config_path}")
    else:
        # Try to load default config
        default_config = Path("config.yaml")
        if default_config.exists():
            config = load_config(default_config)

    # Update config with CLI arguments
    if args.timeout:
        config["timeout"] = args.timeout
    if args.include_dev:
        config["include_dev"] = args.include_dev

    # Validate project path
    project_path = Path(args.path).resolve()
    if not project_path.exists():
        logger.error(f"Project path does not exist: {project_path}")
        return 1

    if not project_path.is_dir():
        logger.error(f"Project path is not a directory: {project_path}")
        return 1

    # Detect project type
    logger.info(f"Scanning project at: {project_path}")
    project_type = detect_project_type(project_path)
    
    if not project_type:
        logger.error("Could not detect project type (Python or Node.js)")
        logger.info("Supported project types:")
        logger.info("  - Python: requirements.txt, pyproject.toml, setup.py")
        logger.info("  - Node.js: package.json, package-lock.json")
        return 1

    logger.info(f"Detected project type: {project_type}")

    try:
        # Perform scan
        scan_result = scan_project(project_path, project_type, config)

        # Generate output
        output_content = ""
        if args.format == "json":
            output_content = json.dumps(scan_result.to_dict(), indent=2)
        elif args.format == "html":
            output_content = generate_report(scan_result, "html")
        elif args.format == "text":
            output_content = generate_report(scan_result, "text")

        # Write output
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(output_content)
            logger.info(f"Report written to: {output_path}")
        else:
            print(output_content)

        # Summary
        logger.info(f"Scan completed:")
        logger.info(f"  - Dependencies scanned: {len(scan_result.dependencies)}")
        logger.info(f"  - Vulnerabilities found: {len(scan_result.vulnerabilities)}")
        
        if scan_result.vulnerabilities:
            by_severity = {}
            for vuln in scan_result.vulnerabilities:
                by_severity[vuln.severity] = by_severity.get(vuln.severity, 0) + 1
            
            for severity, count in sorted(by_severity.items()):
                logger.info(f"    {severity}: {count}")

        # Check if should fail
        if should_fail(scan_result, args.fail_on):
            logger.error(f"Found vulnerabilities with severity >= {args.fail_on}")
            return 2

        return 0

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=args.verbose)
        return 1


if __name__ == "__main__":
    sys.exit(main())