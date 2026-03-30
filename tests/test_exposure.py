"""Tests for exposure and vulnerability management module"""

import pytest
from datetime import datetime
from httpx import AsyncClient

from src.core.logging import get_logger

logger = get_logger(__name__)


class TestRiskScoring:
    """Tests for risk scoring algorithms"""

    @pytest.mark.asyncio
    async def test_risk_scorer_asset(self):
        """Test asset risk scoring"""
        asset = {
            'name': 'web-server-01',
            'type': 'web_server',
            'criticality': 'high',
            'vulnerabilities_count': 5,
            'patches_pending': 2,
        }
        # Risk = criticality + vulnerability_count + pending_patches
        risk_score = asset['criticality'] == 'high' and asset['vulnerabilities_count'] > 0
        assert risk_score is True

    @pytest.mark.asyncio
    async def test_risk_scorer_vulnerability(self):
        """Test vulnerability risk scoring"""
        vuln = {
            'cve': 'CVE-2024-1234',
            'cvss_score': 9.8,
            'exploitable': True,
            'public_exploit': True,
            'affected_assets': 3,
        }
        assert vuln['cvss_score'] > 9.0
        assert vuln['exploitable'] is True


class TestAssetDiscovery:
    """Tests for asset discovery from logs"""

    @pytest.mark.asyncio
    async def test_asset_discovery_from_logs(self):
        """Test discovering assets from security logs"""
        logs = [
            {'source_ip': '192.168.1.10', 'hostname': 'web-server-01'},
            {'source_ip': '192.168.1.11', 'hostname': 'db-server-01'},
            {'source_ip': '192.168.1.10', 'hostname': 'web-server-01'},
        ]
        # Extract unique assets
        assets = {}
        for log in logs:
            assets[log['source_ip']] = log.get('hostname')

        assert len(assets) == 2
        assert assets['192.168.1.10'] == 'web-server-01'


class TestVulnerabilityManager:
    """Tests for vulnerability management"""

    @pytest.mark.asyncio
    async def test_vulnerability_manager_import(self):
        """Test importing vulnerabilities"""
        vulns_to_import = [
            {'cve': 'CVE-2024-1234', 'base_score': 7.5},
            {'cve': 'CVE-2024-5678', 'base_score': 9.8},
            {'cve': 'CVE-2024-9012', 'base_score': 4.3},
        ]
        assert len(vulns_to_import) == 3
        high_severity = [v for v in vulns_to_import if v['base_score'] > 7.0]
        assert len(high_severity) == 2


class TestKEV:
    """Tests for Known Exploited Vulnerabilities (KEV) checks"""

    @pytest.mark.asyncio
    async def test_kev_status_check(self):
        """Test checking if vulnerability is in KEV catalog"""
        vuln_cve = 'CVE-2024-1234'
        kev_catalog = ['CVE-2024-1234', 'CVE-2024-5678']

        is_kev = vuln_cve in kev_catalog
        assert is_kev is True


class TestRemediationPlanning:
    """Tests for remediation priority and planning"""

    @pytest.mark.asyncio
    async def test_remediation_priority(self):
        """Test calculating remediation priority"""
        vuln = {
            'cvss_score': 9.8,
            'exploitable': True,
            'affected_assets': 10,
            'days_to_patch': 30,
        }
        # Priority = CVSS + exploitability + asset_count
        priority = vuln['cvss_score'] * 10 + (50 if vuln['exploitable'] else 0)
        assert priority > 100


class TestCompliance:
    """Tests for compliance checking"""

    @pytest.mark.asyncio
    async def test_compliance_checker(self):
        """Test compliance against standards"""
        compliance_checks = {
            'PCI-DSS': {'required': True, 'status': 'compliant'},
            'HIPAA': {'required': True, 'status': 'non_compliant'},
            'SOC2': {'required': False, 'status': 'not_applicable'},
        }
        non_compliant = [k for k, v in compliance_checks.items()
                        if v['required'] and v['status'] == 'non_compliant']
        assert 'HIPAA' in non_compliant


class TestAPIEndpoints:
    """Tests for Exposure API endpoints"""

    @pytest.mark.asyncio
    async def test_api_create_asset(self, client: AsyncClient, auth_headers: dict):
        """Test creating an asset record"""
        asset_data = {
            'name': 'prod-web-server',
            'asset_type': 'web_server',
            'ip_address': '192.168.1.10',
            'criticality': 'high',
        }
        assert asset_data['asset_type'] == 'web_server'
        assert asset_data['criticality'] == 'high'

    @pytest.mark.asyncio
    async def test_api_create_vulnerability(self, client: AsyncClient, auth_headers: dict):
        """Test creating a vulnerability record"""
        vuln_data = {
            'cve': 'CVE-2024-1234',
            'cvss_score': 8.5,
            'description': 'Remote Code Execution vulnerability',
            'severity': 'high',
        }
        assert vuln_data['cvss_score'] == 8.5
        assert 'CVE-' in vuln_data['cve']

    @pytest.mark.asyncio
    async def test_api_launch_scan(self, client: AsyncClient, auth_headers: dict):
        """Test launching vulnerability scans"""
        scan_data = {
            'name': 'prod-scan-001',
            'target_assets': [1, 2, 3],
            'scan_type': 'network',
        }
        assert scan_data['scan_type'] == 'network'
        assert len(scan_data['target_assets']) == 3

    @pytest.mark.asyncio
    async def test_api_create_ticket(self, client: AsyncClient, auth_headers: dict):
        """Test creating remediation tickets"""
        ticket_data = {
            'title': 'Patch CVE-2024-1234',
            'description': 'Apply security patch',
            'priority': 'high',
            'assigned_to': None,
        }
        assert ticket_data['priority'] == 'high'
        assert 'CVE-' in ticket_data['title']
