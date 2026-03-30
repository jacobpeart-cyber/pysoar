"""Playbook Designer and Execution Engine"""

import asyncio
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from uuid import uuid4

from src.core.logging import get_logger
from src.playbook_builder.models import (
    EdgeType,
    ErrorHandler,
    ExecutionStatus,
    NodeExecutionStatus,
    NodeType,
    PlaybookEdge,
    PlaybookExecution,
    PlaybookNode,
    PlaybookNodeExecution,
    TriggerType,
    VisualPlaybook,
)

logger = get_logger(__name__)


class PlaybookDesigner:
    """Manages playbook design and structure"""

    def __init__(self):
        """Initialize designer"""
        self.validation_errors: list[str] = []

    def create_playbook(
        self,
        organization_id: str,
        name: str,
        description: Optional[str] = None,
        category: str = "custom",
        trigger_type: str = "manual",
    ) -> VisualPlaybook:
        """Create a new playbook"""
        playbook = VisualPlaybook(
            organization_id=organization_id,
            name=name,
            description=description,
            category=category,
            trigger_type=trigger_type,
        )
        logger.info(f"Created playbook: {name}")
        return playbook

    def add_node(
        self,
        playbook: VisualPlaybook,
        node_type: str,
        display_name: str,
        position_x: float,
        position_y: float,
        config: Optional[dict] = None,
        description: Optional[str] = None,
        timeout_seconds: int = 300,
        retry_count: int = 0,
        on_error: str = "stop",
    ) -> PlaybookNode:
        """Add a node to the playbook"""
        node_id = f"node_{uuid4().hex[:8]}"

        node = PlaybookNode(
            playbook_id=playbook.id,
            organization_id=playbook.organization_id,
            node_id=node_id,
            node_type=node_type,
            display_name=display_name,
            description=description,
            position_x=position_x,
            position_y=position_y,
            config=json.dumps(config) if config else None,
            timeout_seconds=timeout_seconds,
            retry_count=retry_count,
            on_error=on_error,
        )
        playbook.nodes.append(node)
        logger.info(f"Added node {node_id} to playbook {playbook.id}")
        return node

    def remove_node(self, playbook: VisualPlaybook, node_id: str) -> bool:
        """Remove a node from the playbook"""
        node = next((n for n in playbook.nodes if n.node_id == node_id), None)
        if not node:
            return False

        # Remove related edges
        playbook.edges = [
            e
            for e in playbook.edges
            if e.source_node_id != node_id and e.target_node_id != node_id
        ]

        playbook.nodes.remove(node)
        logger.info(f"Removed node {node_id} from playbook {playbook.id}")
        return True

    def connect_nodes(
        self,
        playbook: VisualPlaybook,
        source_node_id: str,
        target_node_id: str,
        edge_type: str = "success",
        condition_expression: Optional[str] = None,
        label: Optional[str] = None,
        priority: int = 0,
    ) -> PlaybookEdge:
        """Connect two nodes with an edge"""
        # Verify nodes exist
        source = next((n for n in playbook.nodes if n.node_id == source_node_id), None)
        target = next((n for n in playbook.nodes if n.node_id == target_node_id), None)

        if not source or not target:
            raise ValueError(f"Source or target node not found")

        edge = PlaybookEdge(
            playbook_id=playbook.id,
            organization_id=playbook.organization_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            edge_type=edge_type,
            condition_expression=condition_expression,
            label=label,
            priority=priority,
        )
        playbook.edges.append(edge)
        logger.info(f"Connected {source_node_id} -> {target_node_id}")
        return edge

    def disconnect_nodes(
        self, playbook: VisualPlaybook, source_node_id: str, target_node_id: str
    ) -> bool:
        """Remove edge between two nodes"""
        edge = next(
            (
                e
                for e in playbook.edges
                if e.source_node_id == source_node_id and e.target_node_id == target_node_id
            ),
            None,
        )

        if not edge:
            return False

        playbook.edges.remove(edge)
        logger.info(f"Disconnected {source_node_id} -> {target_node_id}")
        return True

    def validate_playbook(self, playbook: VisualPlaybook) -> tuple[bool, list[str]]:
        """Validate playbook structure"""
        self.validation_errors = []

        # Check for trigger node
        trigger_nodes = [n for n in playbook.nodes if n.node_type == NodeType.TRIGGER.value]
        if not trigger_nodes:
            self.validation_errors.append("Playbook must have at least one trigger node")

        # Check for cycles
        if self._has_cycles(playbook):
            self.validation_errors.append("Playbook contains circular references")

        # Check for unreachable nodes
        unreachable = self._find_unreachable_nodes(playbook)
        if unreachable:
            self.validation_errors.append(f"Unreachable nodes: {', '.join(unreachable)}")

        # Validate node connections
        for node in playbook.nodes:
            outgoing = [e for e in playbook.edges if e.source_node_id == node.node_id]
            # Condition nodes should have conditional edges
            if node.node_type == NodeType.CONDITION.value and not outgoing:
                self.validation_errors.append(
                    f"Condition node {node.node_id} must have outgoing edges"
                )

        return len(self.validation_errors) == 0, self.validation_errors

    def _has_cycles(self, playbook: VisualPlaybook) -> bool:
        """Check if playbook has cycles using DFS"""
        adj_list = {}
        for edge in playbook.edges:
            if edge.source_node_id not in adj_list:
                adj_list[edge.source_node_id] = []
            adj_list[edge.source_node_id].append(edge.target_node_id)

        visited = set()
        rec_stack = set()

        def dfs(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)

            for neighbor in adj_list.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True

            rec_stack.remove(node)
            return False

        for node in playbook.nodes:
            if node.node_id not in visited:
                if dfs(node.node_id):
                    return True

        return False

    def _find_unreachable_nodes(self, playbook: VisualPlaybook) -> list[str]:
        """Find nodes not reachable from trigger"""
        trigger_nodes = [n.node_id for n in playbook.nodes if n.node_type == NodeType.TRIGGER.value]

        reachable = set(trigger_nodes)
        queue = list(trigger_nodes)

        while queue:
            current = queue.pop(0)
            for edge in playbook.edges:
                if edge.source_node_id == current and edge.target_node_id not in reachable:
                    reachable.add(edge.target_node_id)
                    queue.append(edge.target_node_id)

        all_nodes = {n.node_id for n in playbook.nodes}
        return list(all_nodes - reachable)

    def clone_playbook(
        self, playbook: VisualPlaybook, new_name: str, organization_id: Optional[str] = None
    ) -> VisualPlaybook:
        """Clone a playbook"""
        org_id = organization_id or playbook.organization_id

        cloned = VisualPlaybook(
            organization_id=org_id,
            name=new_name,
            description=playbook.description,
            category=playbook.category,
            trigger_type=playbook.trigger_type,
            trigger_config=playbook.trigger_config,
            canvas_data=playbook.canvas_data,
        )

        # Clone nodes
        node_mapping = {}
        for node in playbook.nodes:
            new_node = PlaybookNode(
                playbook_id=cloned.id,
                organization_id=org_id,
                node_id=node.node_id,
                node_type=node.node_type,
                display_name=node.display_name,
                description=node.description,
                position_x=node.position_x,
                position_y=node.position_y,
                config=node.config,
                input_schema=node.input_schema,
                output_schema=node.output_schema,
                timeout_seconds=node.timeout_seconds,
                retry_count=node.retry_count,
                on_error=node.on_error,
            )
            cloned.nodes.append(new_node)
            node_mapping[node.node_id] = new_node.node_id

        # Clone edges
        for edge in playbook.edges:
            new_edge = PlaybookEdge(
                playbook_id=cloned.id,
                organization_id=org_id,
                source_node_id=edge.source_node_id,
                target_node_id=edge.target_node_id,
                edge_type=edge.edge_type,
                condition_expression=edge.condition_expression,
                label=edge.label,
                priority=edge.priority,
            )
            cloned.edges.append(new_edge)

        logger.info(f"Cloned playbook {playbook.id} as {new_name}")
        return cloned

    def export_playbook_json(self, playbook: VisualPlaybook) -> dict:
        """Export playbook as JSON"""
        return {
            "id": playbook.id,
            "name": playbook.name,
            "description": playbook.description,
            "version": playbook.version,
            "category": playbook.category,
            "trigger_type": playbook.trigger_type,
            "trigger_config": json.loads(playbook.trigger_config) if playbook.trigger_config else None,
            "canvas_data": json.loads(playbook.canvas_data) if playbook.canvas_data else None,
            "nodes": [
                {
                    "node_id": n.node_id,
                    "node_type": n.node_type,
                    "display_name": n.display_name,
                    "description": n.description,
                    "position_x": n.position_x,
                    "position_y": n.position_y,
                    "config": json.loads(n.config) if n.config else None,
                    "timeout_seconds": n.timeout_seconds,
                    "retry_count": n.retry_count,
                    "on_error": n.on_error,
                }
                for n in playbook.nodes
            ],
            "edges": [
                {
                    "source_node_id": e.source_node_id,
                    "target_node_id": e.target_node_id,
                    "edge_type": e.edge_type,
                    "condition_expression": e.condition_expression,
                    "label": e.label,
                    "priority": e.priority,
                }
                for e in playbook.edges
            ],
        }

    def import_playbook_json(
        self, org_id: str, playbook_json: dict
    ) -> VisualPlaybook:
        """Import playbook from JSON"""
        playbook = VisualPlaybook(
            organization_id=org_id,
            name=playbook_json.get("name"),
            description=playbook_json.get("description"),
            category=playbook_json.get("category", "custom"),
            trigger_type=playbook_json.get("trigger_type", "manual"),
            trigger_config=json.dumps(playbook_json.get("trigger_config")),
            canvas_data=json.dumps(playbook_json.get("canvas_data")),
        )

        # Import nodes
        for node_data in playbook_json.get("nodes", []):
            node = PlaybookNode(
                playbook_id=playbook.id,
                organization_id=org_id,
                node_id=node_data.get("node_id"),
                node_type=node_data.get("node_type"),
                display_name=node_data.get("display_name"),
                description=node_data.get("description"),
                position_x=node_data.get("position_x", 0),
                position_y=node_data.get("position_y", 0),
                config=json.dumps(node_data.get("config")),
                timeout_seconds=node_data.get("timeout_seconds", 300),
                retry_count=node_data.get("retry_count", 0),
                on_error=node_data.get("on_error", "stop"),
            )
            playbook.nodes.append(node)

        # Import edges
        for edge_data in playbook_json.get("edges", []):
            edge = PlaybookEdge(
                playbook_id=playbook.id,
                organization_id=org_id,
                source_node_id=edge_data.get("source_node_id"),
                target_node_id=edge_data.get("target_node_id"),
                edge_type=edge_data.get("edge_type", "success"),
                condition_expression=edge_data.get("condition_expression"),
                label=edge_data.get("label"),
                priority=edge_data.get("priority", 0),
            )
            playbook.edges.append(edge)

        logger.info(f"Imported playbook: {playbook.name}")
        return playbook


class PlaybookExecutionEngine:
    """Executes playbooks"""

    def __init__(self):
        """Initialize execution engine"""
        self.node_executors = self._init_node_executors()

    def _init_node_executors(self) -> dict[str, Callable]:
        """Initialize node executor functions"""
        return {
            NodeType.ACTION.value: self._action_executor,
            NodeType.CONDITION.value: self._condition_executor,
            NodeType.TRANSFORM.value: self._transform_executor,
            NodeType.DELAY.value: self._delay_executor,
            NodeType.HUMAN_APPROVAL.value: self._human_approval_executor,
            NodeType.ENRICHMENT.value: self._enrichment_executor,
            NodeType.NOTIFICATION.value: self._notification_executor,
            NodeType.SUBPLAYBOOK.value: self._subplaybook_executor,
            NodeType.VARIABLE_SET.value: self._variable_set_executor,
            NodeType.API_CALL.value: self._api_call_executor,
            NodeType.TRIGGER.value: self._trigger_executor,
        }

    async def execute_playbook(
        self,
        playbook: VisualPlaybook,
        trigger_event: Optional[dict] = None,
        variables: Optional[dict] = None,
    ) -> PlaybookExecution:
        """Execute a playbook"""
        execution = PlaybookExecution(
            playbook_id=playbook.id,
            organization_id=playbook.organization_id,
            trigger_event=json.dumps(trigger_event) if trigger_event else None,
            status=ExecutionStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc).isoformat(),
            variables=json.dumps(variables or {}),
        )

        try:
            # Find trigger node
            trigger_nodes = [n for n in playbook.nodes if n.node_type == NodeType.TRIGGER.value]
            if not trigger_nodes:
                execution.status = ExecutionStatus.FAILED.value
                execution.error_message = "No trigger node found"
                return execution

            # Start execution from trigger
            trigger_node = trigger_nodes[0]
            execution_path = [trigger_node.node_id]

            current_node = trigger_node
            runtime_vars = variables or {}

            while current_node:
                # Execute current node
                node_exec = await self.execute_node(
                    current_node, execution, runtime_vars
                )

                if node_exec.status == NodeExecutionStatus.FAILED.value:
                    if current_node.on_error == ErrorHandler.STOP.value:
                        execution.status = ExecutionStatus.FAILED.value
                        execution.error_message = node_exec.error_message
                        break

                execution_path.append(current_node.node_id)

                # Find next node based on edges
                next_node = self._get_next_node(
                    playbook, current_node, node_exec.status, runtime_vars
                )

                current_node = next_node

            execution.status = ExecutionStatus.COMPLETED.value
            execution.completed_at = datetime.now(timezone.utc).isoformat()
            execution.execution_path = json.dumps(execution_path)

        except Exception as e:
            execution.status = ExecutionStatus.FAILED.value
            execution.error_message = str(e)
            logger.error(f"Playbook execution failed: {e}")

        return execution

    async def execute_node(
        self,
        node: PlaybookNode,
        execution: PlaybookExecution,
        variables: dict,
    ) -> PlaybookNodeExecution:
        """Execute a single node"""
        node_exec = PlaybookNodeExecution(
            execution_id=execution.id,
            organization_id=execution.organization_id,
            node_id=node.node_id,
            status=NodeExecutionStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        try:
            executor = self.node_executors.get(node.node_type)
            if not executor:
                raise ValueError(f"Unknown node type: {node.node_type}")

            config = json.loads(node.config) if node.config else {}
            result = await executor(config, variables)

            node_exec.output_data = json.dumps(result)
            node_exec.status = NodeExecutionStatus.COMPLETED.value

        except Exception as e:
            node_exec.status = NodeExecutionStatus.FAILED.value
            node_exec.error_message = str(e)
            logger.error(f"Node execution failed: {e}")

        node_exec.completed_at = datetime.now(timezone.utc).isoformat()
        execution.node_executions.append(node_exec)

        return node_exec

    async def _action_executor(self, config: dict, variables: dict) -> dict:
        """Execute action node"""
        action_type = config.get("action_type")
        params = config.get("params", {})
        logger.info(f"Executing action: {action_type}")
        return {"action": action_type, "result": "success"}

    async def _condition_executor(self, config: dict, variables: dict) -> dict:
        """Execute condition node"""
        expression = config.get("expression")
        result = self.evaluate_condition(expression, variables)
        return {"condition": expression, "result": result}

    async def _transform_executor(self, config: dict, variables: dict) -> dict:
        """Execute transform node"""
        mapping = config.get("mapping", {})
        transformed = {}
        for key, path in mapping.items():
            transformed[key] = self._get_json_path(variables, path)
        return transformed

    async def _delay_executor(self, config: dict, variables: dict) -> dict:
        """Execute delay node"""
        duration_seconds = config.get("duration_seconds", 1)
        await asyncio.sleep(duration_seconds)
        return {"delayed": True, "seconds": duration_seconds}

    async def _human_approval_executor(self, config: dict, variables: dict) -> dict:
        """Execute human approval node"""
        message = config.get("message")
        logger.info(f"Awaiting approval: {message}")
        return {"approval_status": "pending"}

    async def _enrichment_executor(self, config: dict, variables: dict) -> dict:
        """Execute enrichment node"""
        enrichment_type = config.get("enrichment_type")
        return {"enrichment": enrichment_type, "data": {}}

    async def _notification_executor(self, config: dict, variables: dict) -> dict:
        """Execute notification node"""
        channel = config.get("channel")  # slack, teams, email, pagerduty
        message = config.get("message")
        logger.info(f"Sending notification to {channel}: {message}")
        return {"notification": channel, "sent": True}

    async def _subplaybook_executor(self, config: dict, variables: dict) -> dict:
        """Execute subplaybook node"""
        subplaybook_id = config.get("playbook_id")
        logger.info(f"Executing subplaybook: {subplaybook_id}")
        return {"subplaybook": subplaybook_id, "status": "executed"}

    async def _variable_set_executor(self, config: dict, variables: dict) -> dict:
        """Execute variable set node"""
        var_name = config.get("variable_name")
        var_value = config.get("variable_value")
        variables[var_name] = var_value
        return {"variable": var_name, "value": var_value}

    async def _api_call_executor(self, config: dict, variables: dict) -> dict:
        """Execute API call node"""
        url = config.get("url")
        method = config.get("method", "GET")
        logger.info(f"Making API call: {method} {url}")
        return {"api_call": url, "method": method, "status": 200}

    async def _trigger_executor(self, config: dict, variables: dict) -> dict:
        """Execute trigger node"""
        return {"triggered": True}

    def evaluate_condition(self, expression: str, variables: dict) -> bool:
        """Evaluate a condition expression"""
        if not expression:
            return True

        # Simple expression parser for AND/OR/NOT/comparisons
        expression = expression.strip()

        # Handle NOT
        if expression.startswith("NOT "):
            return not self.evaluate_condition(expression[4:], variables)

        # Handle OR
        if " OR " in expression:
            parts = expression.split(" OR ")
            return any(self.evaluate_condition(p.strip(), variables) for p in parts)

        # Handle AND
        if " AND " in expression:
            parts = expression.split(" AND ")
            return all(self.evaluate_condition(p.strip(), variables) for p in parts)

        # Handle comparisons
        for op in ["==", "!=", ">=", "<=", ">", "<", "contains", "matches"]:
            if op in expression:
                parts = expression.split(op)
                if len(parts) == 2:
                    left = self._resolve_value(parts[0].strip(), variables)
                    right = self._resolve_value(parts[1].strip(), variables)

                    if op == "==":
                        return left == right
                    elif op == "!=":
                        return left != right
                    elif op == ">=":
                        return left >= right
                    elif op == "<=":
                        return left <= right
                    elif op == ">":
                        return left > right
                    elif op == "<":
                        return left < right
                    elif op == "contains":
                        return str(right) in str(left)
                    elif op == "matches":
                        return bool(re.search(str(right), str(left)))

        return True

    def _resolve_value(self, value_str: str, variables: dict) -> Any:
        """Resolve a value string to actual value"""
        value_str = value_str.strip()

        # JSON path reference
        if value_str.startswith("$."):
            return self._get_json_path(variables, value_str)

        # Variable reference
        if value_str in variables:
            return variables[value_str]

        # Try to parse as JSON/number/boolean
        try:
            return json.loads(value_str)
        except (json.JSONDecodeError, ValueError):
            return value_str

    def _get_json_path(self, data: dict, path: str) -> Any:
        """Get value from JSON path"""
        if path.startswith("$."):
            path = path[2:]

        parts = path.split(".")
        current = data

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None

        return current

    def _get_next_node(
        self,
        playbook: VisualPlaybook,
        current_node: PlaybookNode,
        node_status: str,
        variables: dict,
    ) -> Optional[PlaybookNode]:
        """Determine next node to execute"""
        # Find outgoing edges
        outgoing_edges = [
            e for e in playbook.edges if e.source_node_id == current_node.node_id
        ]

        # Sort by priority
        outgoing_edges.sort(key=lambda e: e.priority, reverse=True)

        for edge in outgoing_edges:
            # Check edge type match
            if edge.edge_type == EdgeType.SUCCESS.value and node_status != NodeExecutionStatus.COMPLETED.value:
                continue
            if edge.edge_type == EdgeType.FAILURE.value and node_status != NodeExecutionStatus.FAILED.value:
                continue

            # Check condition if present
            if edge.condition_expression:
                if not self.evaluate_condition(edge.condition_expression, variables):
                    continue

            # Find target node
            return next(
                (n for n in playbook.nodes if n.node_id == edge.target_node_id), None
            )

        return None


class TemplateLibrary:
    """Built-in playbook templates"""

    @staticmethod
    def get_templates() -> dict[str, dict]:
        """Get all available templates"""
        return {
            "phishing_response": TemplateLibrary.phishing_response_template(),
            "malware_triage": TemplateLibrary.malware_triage_template(),
            "ransomware_ir": TemplateLibrary.ransomware_ir_template(),
            "brute_force_response": TemplateLibrary.brute_force_response_template(),
            "vulnerability_remediation": TemplateLibrary.vulnerability_remediation_template(),
            "compliance_check": TemplateLibrary.compliance_check_template(),
            "threat_intel_enrichment": TemplateLibrary.threat_intel_enrichment_template(),
            "user_access_review": TemplateLibrary.user_access_review_template(),
            "account_lockout": TemplateLibrary.account_lockout_template(),
            "dlp_violation": TemplateLibrary.dlp_violation_template(),
            "cloud_misconfiguration": TemplateLibrary.cloud_misconfiguration_template(),
            "insider_threat": TemplateLibrary.insider_threat_template(),
            "data_breach_notification": TemplateLibrary.data_breach_notification_template(),
            "patch_deployment": TemplateLibrary.patch_deployment_template(),
            "privilege_escalation": TemplateLibrary.privilege_escalation_template(),
        }

    @staticmethod
    def phishing_response_template() -> dict:
        """Phishing response workflow template"""
        return {
            "name": "Phishing Response",
            "description": "Automated response to phishing emails",
            "category": "incident_response",
            "trigger_type": "alert",
            "nodes": [
                {
                    "node_id": "trigger_1",
                    "node_type": "trigger",
                    "display_name": "Phishing Alert",
                    "position_x": 100,
                    "position_y": 50,
                },
                {
                    "node_id": "enrich_1",
                    "node_type": "enrichment",
                    "display_name": "Enrich Email",
                    "position_x": 100,
                    "position_y": 150,
                    "config": {"enrichment_type": "email_analysis"},
                },
                {
                    "node_id": "condition_1",
                    "node_type": "condition",
                    "display_name": "Is Malicious",
                    "position_x": 100,
                    "position_y": 250,
                },
                {
                    "node_id": "action_1",
                    "node_type": "action",
                    "display_name": "Quarantine Email",
                    "position_x": 250,
                    "position_y": 350,
                },
                {
                    "node_id": "notify_1",
                    "node_type": "notification",
                    "display_name": "Notify SOC",
                    "position_x": 250,
                    "position_y": 450,
                    "config": {"channel": "slack"},
                },
            ],
            "edges": [
                {
                    "source_node_id": "trigger_1",
                    "target_node_id": "enrich_1",
                    "edge_type": "success",
                },
                {
                    "source_node_id": "enrich_1",
                    "target_node_id": "condition_1",
                    "edge_type": "success",
                },
                {
                    "source_node_id": "condition_1",
                    "target_node_id": "action_1",
                    "edge_type": "success",
                },
                {
                    "source_node_id": "action_1",
                    "target_node_id": "notify_1",
                    "edge_type": "success",
                },
            ],
        }

    @staticmethod
    def malware_triage_template() -> dict:
        """Malware triage workflow"""
        return {
            "name": "Malware Triage",
            "description": "Triage and analyze malware samples",
            "category": "threat_hunting",
            "trigger_type": "alert",
            "nodes": [
                {"node_id": "t1", "node_type": "trigger", "display_name": "Malware Alert", "position_x": 0, "position_y": 0},
                {"node_id": "a1", "node_type": "enrichment", "display_name": "Sandbox Detonate", "position_x": 0, "position_y": 100, "config": {"enrichment_type": "sandbox"}},
                {"node_id": "a2", "node_type": "enrichment", "display_name": "VirusTotal Lookup", "position_x": 0, "position_y": 200, "config": {"enrichment_type": "virustotal"}},
                {"node_id": "n1", "node_type": "notification", "display_name": "Alert Team", "position_x": 0, "position_y": 300, "config": {"channel": "email"}},
            ],
            "edges": [
                {"source_node_id": "t1", "target_node_id": "a1", "edge_type": "success"},
                {"source_node_id": "a1", "target_node_id": "a2", "edge_type": "success"},
                {"source_node_id": "a2", "target_node_id": "n1", "edge_type": "success"},
            ],
        }

    @staticmethod
    def ransomware_ir_template() -> dict:
        """Ransomware incident response"""
        return {
            "name": "Ransomware IR",
            "description": "Ransomware incident response workflow",
            "category": "incident_response",
            "trigger_type": "alert",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def brute_force_response_template() -> dict:
        """Brute force attack response"""
        return {
            "name": "Brute Force Response",
            "description": "Automatic response to brute force attacks",
            "category": "incident_response",
            "trigger_type": "threshold",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def vulnerability_remediation_template() -> dict:
        """Vulnerability remediation workflow"""
        return {
            "name": "Vulnerability Remediation",
            "description": "Remediate discovered vulnerabilities",
            "category": "remediation",
            "trigger_type": "alert",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def compliance_check_template() -> dict:
        """Compliance check workflow"""
        return {
            "name": "Compliance Check",
            "description": "Automated compliance verification",
            "category": "compliance",
            "trigger_type": "schedule",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def threat_intel_enrichment_template() -> dict:
        """Threat intelligence enrichment"""
        return {
            "name": "Threat Intel Enrichment",
            "description": "Enrich alerts with threat intelligence",
            "category": "enrichment",
            "trigger_type": "alert",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def user_access_review_template() -> dict:
        """User access review workflow"""
        return {
            "name": "User Access Review",
            "description": "Review and audit user access",
            "category": "compliance",
            "trigger_type": "schedule",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def account_lockout_template() -> dict:
        """Account lockout response"""
        return {
            "name": "Account Lockout",
            "description": "Handle suspicious account lockouts",
            "category": "incident_response",
            "trigger_type": "alert",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def dlp_violation_template() -> dict:
        """DLP violation response"""
        return {
            "name": "DLP Violation",
            "description": "Respond to data loss prevention violations",
            "category": "incident_response",
            "trigger_type": "alert",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def cloud_misconfiguration_template() -> dict:
        """Cloud misconfiguration remediation"""
        return {
            "name": "Cloud Misconfiguration",
            "description": "Detect and remediate cloud misconfigurations",
            "category": "remediation",
            "trigger_type": "alert",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def insider_threat_template() -> dict:
        """Insider threat response"""
        return {
            "name": "Insider Threat",
            "description": "Insider threat detection and response",
            "category": "incident_response",
            "trigger_type": "alert",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def data_breach_notification_template() -> dict:
        """Data breach notification workflow"""
        return {
            "name": "Data Breach Notification",
            "description": "Handle data breach notifications",
            "category": "notification",
            "trigger_type": "alert",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def patch_deployment_template() -> dict:
        """Patch deployment workflow"""
        return {
            "name": "Patch Deployment",
            "description": "Automated patch deployment",
            "category": "remediation",
            "trigger_type": "schedule",
            "nodes": [],
            "edges": [],
        }

    @staticmethod
    def privilege_escalation_template() -> dict:
        """Privilege escalation response"""
        return {
            "name": "Privilege Escalation",
            "description": "Detect and respond to privilege escalation",
            "category": "incident_response",
            "trigger_type": "alert",
            "nodes": [],
            "edges": [],
        }
