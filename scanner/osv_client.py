import json
import logging
from typing import Dict, List, Any, Optional
import requests
from requests.exceptions import RequestException

from scanner.models import Vulnerability, Package, Ecosystem

logger = logging.getLogger(__name__)

class OSVClient:
    """Client for interacting with the OSV API."""

    BASE_URL = "https://api.osv.dev/v1"
    QUERY_ENDPOINT = f"{BASE_URL}/query"
    BATCH_QUERY_ENDPOINT = f"{BASE_URL}/querybatch"
    VULN_ENDPOINT = f"{BASE_URL}/vulns"

    def __init__(self, timeout: int = 30):
        """
        Initialize the OSV client.

        Args:
            timeout: Request timeout in seconds.
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "depscan/1.0"
        })

    def query_package(self, package: Package) -> List[Vulnerability]:
        """
        Query vulnerabilities for a single package.

        Args:
            package: Package object containing name, version, and ecosystem.

        Returns:
            List of Vulnerability objects.
        """
        payload = {
            "package": {
                "name": package.name,
                "ecosystem": package.ecosystem.value
            },
            "version": package.version
        }
        try:
            response = self.session.post(
                self.QUERY_ENDPOINT,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_vulnerabilities(data, package)
        except RequestException as e:
            logger.error(f"Failed to query OSV API for {package.name}: {e}")
            return []
        except (KeyError, ValueError, TypeError) as e:
            logger.error(f"Failed to parse OSV API response for {package.name}: {e}")
            return []

    def query_batch(self, packages: List[Package]) -> Dict[str, List[Vulnerability]]:
        """
        Query vulnerabilities for multiple packages in a single batch request.

        Args:
            packages: List of Package objects.

        Returns:
            Dictionary mapping package identifiers to lists of Vulnerability objects.
        """
        queries = []
        for package in packages:
            queries.append({
                "package": {
                    "name": package.name,
                    "ecosystem": package.ecosystem.value
                },
                "version": package.version
            })

        payload = {"queries": queries}
        try:
            response = self.session.post(
                self.BATCH_QUERY_ENDPOINT,
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_batch_response(data, packages)
        except RequestException as e:
            logger.error(f"Failed to query OSV API batch: {e}")
            return {p.identifier: [] for p in packages}
        except (KeyError, ValueError, TypeError) as e:
            logger.error(f"Failed to parse OSV API batch response: {e}")
            return {p.identifier: [] for p in packages}

    def get_vulnerability(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch detailed information for a specific vulnerability.

        Args:
            vuln_id: Vulnerability ID (e.g., "GHSA-xxxx-xxxx-xxxx").

        Returns:
            Dictionary with vulnerability details or None if not found.
        """
        try:
            response = self.session.get(
                f"{self.VULN_ENDPOINT}/{vuln_id}",
                timeout=self.timeout
            )
            response.raise_for_status()
            return response.json()
        except RequestException as e:
            logger.error(f"Failed to fetch vulnerability {vuln_id}: {e}")
            return None

    def _parse_vulnerabilities(self, data: Dict[str, Any], package: Package) -> List[Vulnerability]:
        """Parse OSV API response into Vulnerability objects."""
        vulnerabilities = []
        if "vulns" not in data:
            return vulnerabilities

        for vuln_data in data["vulns"]:
            try:
                vuln = Vulnerability(
                    id=vuln_data.get("id", ""),
                    package=package,
                    summary=vuln_data.get("summary", ""),
                    details=vuln_data.get("details", ""),
                    severity=vuln_data.get("severity", []),
                    affected_versions=self._extract_affected_versions(vuln_data),
                    references=vuln_data.get("references", []),
                    published=vuln_data.get("published"),
                    modified=vuln_data.get("modified"),
                    withdrawn=vuln_data.get("withdrawn")
                )
                vulnerabilities.append(vuln)
            except (KeyError, ValueError, TypeError) as e:
                logger.warning(f"Skipping malformed vulnerability data: {e}")
                continue

        return vulnerabilities

    def _parse_batch_response(self, data: Dict[str, Any], packages: List[Package]) -> Dict[str, List[Vulnerability]]:
        """Parse OSV API batch response."""
        results = {}
        if "results" not in data:
            return {p.identifier: [] for p in packages}

        for idx, result in enumerate(data["results"]):
            package = packages[idx] if idx < len(packages) else None
            if not package:
                continue

            if "vulns" in result:
                vulnerabilities = self._parse_vulnerabilities(result, package)
                results[package.identifier] = vulnerabilities
            else:
                results[package.identifier] = []

        # Ensure all packages are in the results
        for package in packages:
            if package.identifier not in results:
                results[package.identifier] = []

        return results

    def _extract_affected_versions(self, vuln_data: Dict[str, Any]) -> List[str]:
        """Extract affected versions from vulnerability data."""
        affected_versions = []
        if "affected" not in vuln_data:
            return affected_versions

        for affected in vuln_data["affected"]:
            if "versions" in affected:
                affected_versions.extend(affected["versions"])
            elif "ranges" in affected:
                for range_data in affected["ranges"]:
                    if "events" in range_data:
                        for event in range_data["events"]:
                            if "introduced" in event:
                                affected_versions.append(event["introduced"])
                            if "fixed" in event:
                                affected_versions.append(event["fixed"])
                            if "last_affected" in event:
                                affected_versions.append(event["last_affected"])

        return list(set(affected_versions))  # Remove duplicates

    def close(self):
        """Close the HTTP session."""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()