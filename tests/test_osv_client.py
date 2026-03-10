import json
from unittest.mock import patch, Mock
import pytest
from scanner.osv_client import OSVClient, OSVQuery, OSVResponse, Vulnerability


class TestOSVQuery:
    def test_osv_query_creation(self):
        query = OSVQuery(package="requests", version="2.28.2", ecosystem="PyPI")
        assert query.package == "requests"
        assert query.version == "2.28.2"
        assert query.ecosystem == "PyPI"

    def test_osv_query_to_dict(self):
        query = OSVQuery(package="express", version="4.18.2", ecosystem="npm")
        expected = {
            "package": {"name": "express", "ecosystem": "npm"},
            "version": "4.18.2"
        }
        assert query.to_dict() == expected

    def test_osv_query_from_dict(self):
        data = {
            "package": {"name": "flask", "ecosystem": "PyPI"},
            "version": "2.2.3"
        }
        query = OSVQuery.from_dict(data)
        assert query.package == "flask"
        assert query.version == "2.2.3"
        assert query.ecosystem == "PyPI"


class TestVulnerability:
    def test_vulnerability_creation(self):
        vuln = Vulnerability(
            id="GHSA-xxxx-xxxx-xxxx",
            summary="Test vulnerability",
            details="Detailed description",
            severity="HIGH",
            references=["https://example.com"],
            affected_versions=["<2.0.0"]
        )
        assert vuln.id == "GHSA-xxxx-xxxx-xxxx"
        assert vuln.summary == "Test vulnerability"
        assert vuln.severity == "HIGH"
        assert len(vuln.references) == 1
        assert vuln.affected_versions == ["<2.0.0"]

    def test_vulnerability_from_osv(self):
        osv_data = {
            "id": "CVE-2021-12345",
            "summary": "Test CVE",
            "details": "Details here",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "references": [{"url": "https://nvd.nist.gov"}],
            "affected": [{
                "versions": ["<1.2.3"]
            }]
        }
        vuln = Vulnerability.from_osv(osv_data)
        assert vuln.id == "CVE-2021-12345"
        assert vuln.summary == "Test CVE"
        assert vuln.severity == "7.5"
        assert vuln.references == ["https://nvd.nist.gov"]
        assert vuln.affected_versions == ["<1.2.3"]

    def test_vulnerability_from_osv_no_severity(self):
        osv_data = {
            "id": "GHSA-yyyy-yyyy-yyyy",
            "summary": "No severity",
            "details": "",
            "references": [],
            "affected": [{"versions": []}]
        }
        vuln = Vulnerability.from_osv(osv_data)
        assert vuln.severity == "UNKNOWN"


class TestOSVResponse:
    def test_osv_response_creation(self):
        vuln = Vulnerability(id="TEST-001", summary="Test", severity="MEDIUM")
        response = OSVResponse(
            query=OSVQuery(package="test", version="1.0", ecosystem="test"),
            vulnerabilities=[vuln]
        )
        assert response.query.package == "test"
        assert len(response.vulnerabilities) == 1
        assert response.vulnerabilities[0].id == "TEST-001"

    def test_osv_response_from_api(self):
        api_response = {
            "vulns": [
                {
                    "id": "CVE-2022-12345",
                    "summary": "Critical bug",
                    "details": "Details",
                    "severity": [{"type": "CVSS_V3", "score": "9.8"}],
                    "references": [{"url": "https://cve.mitre.org"}],
                    "affected": [{"versions": ["<2.0.0"]}]
                }
            ]
        }
        query = OSVQuery(package="lib", version="1.5.0", ecosystem="npm")
        response = OSVResponse.from_api(api_response, query)
        assert response.query == query
        assert len(response.vulnerabilities) == 1
        assert response.vulnerabilities[0].id == "CVE-2022-12345"
        assert response.vulnerabilities[0].severity == "9.8"

    def test_osv_response_from_api_empty(self):
        api_response = {}
        query = OSVQuery(package="safe", version="3.0.0", ecosystem="PyPI")
        response = OSVResponse.from_api(api_response, query)
        assert response.query == query
        assert len(response.vulnerabilities) == 0


class TestOSVClient:
    @pytest.fixture
    def client(self):
        return OSVClient()

    def test_init_default_endpoint(self):
        client = OSVClient()
        assert client.endpoint == "https://api.osv.dev/v1/query"

    def test_init_custom_endpoint(self):
        client = OSVClient(endpoint="https://custom.osv.dev/query")
        assert client.endpoint == "https://custom.osv.dev/query"

    @patch('scanner.osv_client.requests.post')
    def test_query_success(self, mock_post, client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulns": [
                {
                    "id": "GHSA-abc1-abc2-abc3",
                    "summary": "Mock vulnerability",
                    "details": "Mock details",
                    "severity": [{"type": "CVSS_V3", "score": "5.0"}],
                    "references": [{"url": "https://github.com/advisories"}],
                    "affected": [{"versions": ["<3.0.0"]}]
                }
            ]
        }
        mock_post.return_value = mock_response

        query = OSVQuery(package="mocklib", version="2.5.0", ecosystem="npm")
        response = client.query(query)

        assert mock_post.called
        call_args = mock_post.call_args
        assert call_args[0][0] == client.endpoint
        assert json.loads(call_args[1]['data']) == query.to_dict()
        assert call_args[1]['headers']['Content-Type'] == 'application/json'

        assert response.query == query
        assert len(response.vulnerabilities) == 1
        assert response.vulnerabilities[0].id == "GHSA-abc1-abc2-abc3"

    @patch('scanner.osv_client.requests.post')
    def test_query_http_error(self, mock_post, client):
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = Exception("HTTP Error")
        mock_post.return_value = mock_response

        query = OSVQuery(package="error", version="1.0", ecosystem="test")
        with pytest.raises(Exception, match="HTTP Error"):
            client.query(query)

    @patch('scanner.osv_client.requests.post')
    def test_query_network_error(self, mock_post, client):
        mock_post.side_effect = ConnectionError("Network failure")

        query = OSVQuery(package="net", version="1.0", ecosystem="test")
        with pytest.raises(ConnectionError, match="Network failure"):
            client.query(query)

    @patch('scanner.osv_client.requests.post')
    def test_query_batch_success(self, mock_post, client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {
                    "vulns": [
                        {
                            "id": "CVE-2020-1111",
                            "summary": "First vuln",
                            "severity": [{"type": "CVSS_V3", "score": "8.1"}],
                            "references": [],
                            "affected": [{"versions": ["<1.0.0"]}]
                        }
                    ]
                },
                {
                    "vulns": [
                        {
                            "id": "CVE-2020-2222",
                            "summary": "Second vuln",
                            "severity": [],
                            "references": [],
                            "affected": [{"versions": ["<2.0.0"]}]
                        }
                    ]
                }
            ]
        }
        mock_post.return_value = mock_response

        queries = [
            OSVQuery(package="pkg1", version="0.9.0", ecosystem="PyPI"),
            OSVQuery(package="pkg2", version="1.5.0", ecosystem="npm")
        ]
        responses = client.query_batch(queries)

        assert mock_post.called
        call_args = mock_post.call_args
        assert call_args[0][0] == client.endpoint.replace('query', 'querybatch')
        request_data = json.loads(call_args[1]['data'])
        assert len(request_data['queries']) == 2
        assert request_data['queries'][0]['package']['name'] == "pkg1"

        assert len(responses) == 2
        assert responses[0].query == queries[0]
        assert responses[0].vulnerabilities[0].id == "CVE-2020-1111"
        assert responses[1].query == queries[1]
        assert responses[1].vulnerabilities[0].severity == "UNKNOWN"

    @patch('scanner.osv_client.requests.post')
    def test_query_batch_empty(self, mock_post, client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"results": []}
        mock_post.return_value = mock_response

        responses = client.query_batch([])
        assert responses == []
        assert not mock_post.called

    @patch('scanner.osv_client.requests.post')
    def test_query_batch_partial_failure(self, mock_post, client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "results": [
                {"vulns": []},
                {"error": "Invalid query"}
            ]
        }
        mock_post.return_value = mock_response

        queries = [
            OSVQuery(package="good", version="1.0", ecosystem="PyPI"),
            OSVQuery(package="bad", version="invalid", ecosystem="npm")
        ]
        responses = client.query_batch(queries)

        assert len(responses) == 2
        assert len(responses[0].vulnerabilities) == 0
        assert len(responses[1].vulnerabilities) == 0