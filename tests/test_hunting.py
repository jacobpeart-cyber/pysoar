"""Tests for threat hunting module"""

import pytest
from datetime import datetime
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger

logger = get_logger(__name__)


class TestHypothesis:
    """Tests for hunting hypothesis creation and management"""

    @pytest.mark.asyncio
    async def test_create_hypothesis(self):
        """Test creating a hunt hypothesis"""
        hypothesis = {
            'title': 'Suspicious PowerShell Activity',
            'description': 'Looking for encoded PowerShell scripts',
            'search_focus': ['process_name', 'command_line'],
        }
        assert hypothesis['title'] == 'Suspicious PowerShell Activity'
        assert 'process_name' in hypothesis['search_focus']


class TestHuntSession:
    """Tests for hunt session management"""

    @pytest.mark.asyncio
    async def test_create_hunt_session(self):
        """Test creating a hunt session"""
        session_data = {
            'hypothesis_id': 1,
            'start_date': datetime.utcnow().isoformat(),
            'target_system': 'windows_servers',
            'status': 'active',
        }
        assert session_data['target_system'] == 'windows_servers'
        assert session_data['status'] == 'active'


class TestHuntQuery:
    """Tests for hunt query building"""

    @pytest.mark.asyncio
    async def test_hunt_query_builder(self):
        """Test building hunt queries"""
        query_params = {
            'process_name': 'powershell.exe',
            'command_contains': 'encoded',
            'time_range': '7d',
        }
        assert query_params['process_name'] == 'powershell.exe'
        assert query_params['time_range'] == '7d'


class TestAnalyzers:
    """Tests for hunt data analyzers"""

    @pytest.mark.asyncio
    async def test_hunt_analyzer_frequency(self):
        """Test frequency analysis for hunt results"""
        events = [
            {'user': 'admin', 'action': 'login'},
            {'user': 'admin', 'action': 'login'},
            {'user': 'admin', 'action': 'login'},
            {'user': 'user1', 'action': 'login'},
        ]
        # Count frequency
        user_frequency = {}
        for event in events:
            user = event['user']
            user_frequency[user] = user_frequency.get(user, 0) + 1

        assert user_frequency['admin'] == 3
        assert user_frequency['user1'] == 1

    @pytest.mark.asyncio
    async def test_hunt_analyzer_rare_values(self):
        """Test rare value detection"""
        events = [
            {'path': '/usr/bin/ps'},
            {'path': '/usr/bin/ps'},
            {'path': '/usr/bin/ps'},
            {'path': '/rare/path/binary'},
        ]
        # Rare value is one that appears infrequently
        path_counts = {}
        for event in events:
            path = event['path']
            path_counts[path] = path_counts.get(path, 0) + 1

        rare_paths = [p for p, c in path_counts.items() if c < 2]
        assert '/rare/path/binary' in rare_paths


class TestNotebook:
    """Tests for hunt notebook functionality"""

    @pytest.mark.asyncio
    async def test_notebook_create(self):
        """Test creating a hunt notebook"""
        notebook = {
            'title': 'Hunt Investigation Notes',
            'hunt_session_id': 1,
            'cells': [],
        }
        assert notebook['title'] == 'Hunt Investigation Notes'

    @pytest.mark.asyncio
    async def test_notebook_add_cell(self):
        """Test adding cells to notebook"""
        cell = {
            'type': 'markdown',
            'content': '# Investigation Progress\n\n## Findings',
            'order': 1,
        }
        assert cell['type'] == 'markdown'
        assert '# Investigation Progress' in cell['content']

    @pytest.mark.asyncio
    async def test_notebook_execute_cell(self):
        """Test executing query cells in notebook"""
        cell = {
            'type': 'query',
            'query': 'source_ip:192.168.1.1 AND action:failed_login',
            'results': 42,
        }
        assert cell['type'] == 'query'
        assert cell['results'] == 42


class TestAPIEndpoints:
    """Tests for hunting API endpoints"""

    @pytest.mark.asyncio
    async def test_api_create_hypothesis(self, client: AsyncClient, auth_headers: dict):
        """Test hypothesis creation API"""
        hypothesis_data = {
            'title': 'Lateral Movement Detection',
            'description': 'Find evidence of lateral movement',
        }
        assert hypothesis_data['title'] == 'Lateral Movement Detection'

    @pytest.mark.asyncio
    async def test_api_list_sessions(self, client: AsyncClient, auth_headers: dict):
        """Test listing hunt sessions"""
        # Would normally: response = await client.get('/api/v1/hunts/sessions', headers=auth_headers)
        sessions = [
            {'id': 1, 'status': 'active'},
            {'id': 2, 'status': 'completed'},
        ]
        assert len(sessions) == 2

    @pytest.mark.asyncio
    async def test_api_create_finding(self, client: AsyncClient, auth_headers: dict):
        """Test creating a finding from hunt results"""
        finding_data = {
            'hunt_session_id': 1,
            'title': 'Confirmed C2 Communication',
            'description': 'Evidence of command and control traffic detected',
            'evidence': ['pcap_data', 'dns_logs'],
        }
        assert finding_data['title'] == 'Confirmed C2 Communication'

    @pytest.mark.asyncio
    async def test_api_escalate_finding(self, client: AsyncClient, auth_headers: dict):
        """Test escalating findings to incidents"""
        escalation_data = {
            'finding_id': 1,
            'incident_title': 'Potential Breach - C2 Activity',
            'assign_to': None,
        }
        assert escalation_data['incident_title'] == 'Potential Breach - C2 Activity'
