"""Endpoint-agent block_ip / unblock_ip safety-guard tests.

These cover the pure-validation logic that runs BEFORE any firewall
subprocess is invoked: bad input and dangerous targets must be refused
so a compromised/buggy playbook can't cut the agent off from PySOAR or
break the host. The actual iptables / Windows Firewall dispatch is not
exercised here (it needs a real host firewall); it is guarded by the
management-server-IP and loopback refusals proven below.
"""

import sys
from pathlib import Path

import pytest

# The endpoint agent ships as a standalone script under agent/.
_AGENT_DIR = str(Path(__file__).resolve().parents[2] / "agent")
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

import pysoar_agent as agent  # noqa: E402


def test_handlers_registered():
    assert agent.IR_HANDLERS.get("block_ip") is agent._handle_block_ip
    assert agent.IR_HANDLERS.get("unblock_ip") is agent._handle_unblock_ip


@pytest.mark.parametrize("bad", ["not-an-ip", "10.0.0.999", "example.com", "10.0.0.0/8"])
def test_block_ip_rejects_non_ip(bad):
    res = agent._handle_block_ip({"ip": bad})
    assert res["status"] == "rejected"


@pytest.mark.parametrize("empty", [None, "", "   "])
def test_block_ip_requires_ip(empty):
    res = agent._handle_block_ip({"ip": empty})
    assert res["status"] == "error"
    assert "required" in res["stderr"].lower()


@pytest.mark.parametrize("dangerous", ["127.0.0.1", "::1", "0.0.0.0", "::"])
def test_block_ip_refuses_loopback_and_unspecified(dangerous):
    res = agent._handle_block_ip({"ip": dangerous})
    assert res["status"] == "rejected"
    assert "loopback" in res["stderr"].lower() or "unspecified" in res["stderr"].lower()


def test_block_ip_refuses_management_server(monkeypatch):
    monkeypatch.setattr(agent, "_MANAGEMENT_SERVER_IPS", {"100.27.62.155"})
    res = agent._handle_block_ip({"ip": "100.27.62.155"})
    assert res["status"] == "rejected"
    assert "management server" in res["stderr"].lower()


def test_unblock_ip_validates_input():
    # unblock shares the same parser: garbage in is refused, never a
    # blind firewall-rule sweep.
    assert agent._handle_unblock_ip({"ip": "not-an-ip"})["status"] == "rejected"
    assert agent._handle_unblock_ip({"ip": ""})["status"] == "error"


def test_block_rule_name_is_sanitized():
    # IPv6 colons and any non [A-Za-z0-9.] must not survive into the
    # Windows DisplayName (prevents argument breakout).
    name = agent._block_rule_name("fe80::1")
    assert name.startswith("pysoar-block-")
    assert ":" not in name
