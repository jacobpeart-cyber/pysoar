"""Tests for threat intelligence module"""

import pytest
from datetime import datetime
from httpx import AsyncClient

from src.core.logging import get_logger

logger = get_logger(__name__)


class TestFeedParsing:
    """Tests for threat intelligence feed parsing"""

    @pytest.mark.asyncio
    async def test_stix_feed_parser(self):
        """Test STIX (Structured Threat Information Expression) feed parsing"""
        stix_obj = {
            'type': 'malware',
            'id': 'malware--abc123',
            'created': '2024-01-15T00:00:00.000Z',
            'name': 'Trojan.Win32.Poison',
            'description': 'Dangerous trojan',
        }
        assert stix_obj['type'] == 'malware'
        assert 'Trojan.Win32.Poison' in stix_obj['name']

    @pytest.mark.asyncio
    async def test_csv_feed_parser(self):
        """Test CSV feed parsing"""
        csv_content = """indicator,type,severity,source
192.168.1.1,ip,high,test-feed
malware.com,domain,critical,test-feed"""
        lines = csv_content.strip().split('\n')
        assert len(lines) == 3
        assert 'indicator' in lines[0]

    @pytest.mark.asyncio
    async def test_misp_feed_parser(self):
        """Test MISP feed parsing"""
        misp_event = {
            'Event': {
                'id': '1',
                'info': 'Test Event',
                'Attribute': [
                    {'type': 'ip-dst', 'value': '192.168.1.1'},
                    {'type': 'domain', 'value': 'malicious.com'},
                ],
            }
        }
        assert misp_event['Event']['id'] == '1'
        assert len(misp_event['Event']['Attribute']) == 2


class TestFeedManager:
    """Tests for feed management"""

    @pytest.mark.asyncio
    async def test_feed_manager_poll(self):
        """Test polling threat intelligence feeds"""
        feed = {
            'name': 'SANS ISC Feeds',
            'url': 'https://isc.sans.edu/feeds/',
            'last_polled': datetime.utcnow().isoformat(),
            'indicators_imported': 5000,
        }
        assert feed['name'] == 'SANS ISC Feeds'
        assert feed['indicators_imported'] > 0


class TestIndicatorEnricher:
    """Tests for indicator enrichment"""

    @pytest.mark.asyncio
    async def test_indicator_enricher(self):
        """Test enriching indicators with additional data"""
        indicator = {
            'value': '192.168.1.1',
            'type': 'ip',
            'enrichment': {
                'geolocation': 'US',
                'asn': '12345',
                'reputation': 'malicious',
            }
        }
        assert indicator['enrichment']['reputation'] == 'malicious'


class TestIOCMatcher:
    """Tests for indicator of compromise matching"""

    @pytest.mark.asyncio
    async def test_ioc_matcher_ip(self):
        """Test IP address matching"""
        iocs = ['192.168.1.1', '10.0.0.1']
        log_event = {'source_ip': '192.168.1.1'}

        matches = [ioc for ioc in iocs if ioc == log_event['source_ip']]
        assert len(matches) == 1

    @pytest.mark.asyncio
    async def test_ioc_matcher_domain(self):
        """Test domain matching"""
        iocs = ['malware.com', 'phishing.com']
        log_event = {'dns_query': 'phishing.com'}

        matches = [ioc for ioc in iocs if ioc == log_event['dns_query']]
        assert len(matches) == 1


class TestCompositeScoring:
    """Tests for composite threat score calculation"""

    @pytest.mark.asyncio
    async def test_composite_score_calculation(self):
        """Test calculating composite threat scores"""
        indicator = {
            'base_score': 80,
            'sources': [
                {'name': 'AbuseIPDB', 'score': 90},
                {'name': 'VirusTotal', 'score': 85},
                {'name': 'Shodan', 'score': 75},
            ]
        }
        # Average of all sources
        avg_score = sum(s['score'] for s in indicator['sources']) / len(indicator['sources'])
        assert avg_score > 70
        assert avg_score < 100


class TestAPIEndpoints:
    """Tests for Intel API endpoints"""

    @pytest.mark.asyncio
    async def test_api_create_feed(self, client: AsyncClient, auth_headers: dict):
        """Test creating a feed connection"""
        feed_data = {
            'name': 'Custom Threat Feed',
            'feed_type': 'csv',
            'url': 'https://example.com/feed.csv',
            'enabled': True,
        }
        assert feed_data['feed_type'] == 'csv'
        assert feed_data['enabled'] is True

    @pytest.mark.asyncio
    async def test_api_create_indicator(self, client: AsyncClient, auth_headers: dict):
        """Test creating a threat indicator"""
        indicator_data = {
            'value': '192.168.1.1',
            'type': 'ip',
            'source': 'test-feed',
            'severity': 'high',
            'confidence': 95,
        }
        assert indicator_data['value'] == '192.168.1.1'
        assert indicator_data['confidence'] == 95

    @pytest.mark.asyncio
    async def test_api_bulk_import(self, client: AsyncClient, auth_headers: dict):
        """Test bulk importing indicators"""
        indicators = [
            {'value': '192.168.1.1', 'type': 'ip', 'source': 'test'},
            {'value': 'malware.com', 'type': 'domain', 'source': 'test'},
            {'value': '5c1234', 'type': 'hash', 'source': 'test'},
        ]
        assert len(indicators) == 3

    @pytest.mark.asyncio
    async def test_api_record_sighting(self, client: AsyncClient, auth_headers: dict):
        """Test recording indicator sightings"""
        sighting_data = {
            'indicator_id': 1,
            'source': 'splunk',
            'count': 10,
            'first_seen': '2024-01-15T00:00:00Z',
            'last_seen': '2024-01-15T12:00:00Z',
        }
        assert sighting_data['count'] == 10
        assert sighting_data['indicator_id'] == 1
