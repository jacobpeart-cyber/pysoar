"""Playbook Designer and Execution Engine"""

import asyncio
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.core.utils import safe_json_loads
from src.playbook_builder.models import (
    EdgeType,
    ErrorHandler,
    ExecutionStatus,
    NodeExecutionStatus,
    NodeType,
    PlaybookEdge,
    VisualPlaybookExecution,
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


#: Node types the engine cannot execute yet, with the reason shown to the user.
NOT_IMPLEMENTED_NODE_TYPES: dict[str, str] = {
    NodeType.HUMAN_APPROVAL.value: (
        "human_approval nodes are not implemented: visual runs cannot pause for approval. High-blast "
        "containment already waits in the endpoint-agent approval queue."
    ),
    NodeType.SUBPLAYBOOK.value: "subplaybook nodes are not implemented",
    NodeType.LOOP.value: "loop nodes are not implemented",
    NodeType.PARALLEL.value: "parallel nodes are not implemented",
    NodeType.ERROR_HANDLER.value: "error_handler nodes are not implemented; use on_error and failure edges",
}

#: ``action`` node ``action_type`` values executed through the classic step
#: handlers (src.services.playbook_engine), plus the builder-only agent_command.
ACTION_NODE_TYPES: frozenset[str] = frozenset({
    "block_ip", "isolate_host", "disable_user", "quarantine_file", "create_ticket",
    "integration_action", "http_request", "update_alert", "update_incident", "create_incident",
    "add_comment", "assign_to", "agent_command",
})

ENRICHMENT_TYPES: frozenset[str] = frozenset({"ip", "domain", "hash"})

NODE_COMPLETED = NodeExecutionStatus.COMPLETED.value
NODE_FAILED = NodeExecutionStatus.FAILED.value
NODE_AWAITING_INTEGRATION = "awaiting_integration"
NODE_QUEUED_FOR_APPROVAL = "queued_for_approval"
NODE_MANUAL_REQUIRED = "manual_required"
NODE_NOT_IMPLEMENTED = "not_implemented"
NODE_FORBIDDEN = "forbidden_privileged_node"

#: Visual run status when it finished without errors but some node did not
#: complete (awaiting an integration / approval). Never reported as completed.
RUN_PARTIAL = "partial"

MAX_NODE_STEPS = 200
MAX_DELAY_SECONDS = 60


class PlaybookExecutionEngine:
    """Executes visual playbooks node by node.

    Side-effecting nodes run through the same code paths as classic playbook
    steps (``src.services.playbook_engine.run_step_in_runtime``): containment
    via ``src.services.containment``, integrations via ``ActionExecutor``,
    notifications via the tenant's own settings. Node types that cannot run
    are reported by :meth:`unsupported_nodes` (the API answers 501 before a
    run starts) and fail the node if they are reached anyway.
    """

    def __init__(
        self,
        db: Optional[AsyncSession] = None,
        *,
        actor: Optional[str] = None,
        actor_user_id: Optional[str] = None,
    ):
        """``db`` is the session node side effects and node executions are written to."""
        self.db = db
        self.actor = actor
        self.actor_user_id = actor_user_id
        self.node_executors = self._init_node_executors()

    def _init_node_executors(self) -> dict[str, Callable]:
        """Initialize node executor functions"""
        return {
            NodeType.TRIGGER.value: self._trigger_executor,
            NodeType.ACTION.value: self._action_executor,
            NodeType.CONDITION.value: self._condition_executor,
            NodeType.TRANSFORM.value: self._transform_executor,
            NodeType.DELAY.value: self._delay_executor,
            NodeType.ENRICHMENT.value: self._enrichment_executor,
            NodeType.NOTIFICATION.value: self._notification_executor,
            NodeType.VARIABLE_SET.value: self._variable_set_executor,
            NodeType.API_CALL.value: self._api_call_executor,
        }

    # ------------------------------------------------------------------
    # Static executability check
    # ------------------------------------------------------------------

    @staticmethod
    def _config(node: PlaybookNode) -> dict:
        try:
            config = json.loads(node.config) if node.config else {}
        except (TypeError, json.JSONDecodeError):
            return {"__invalid__": True}
        if config is None:
            return {}
        return config if isinstance(config, dict) else {"__invalid__": True}

    def node_problem(self, node: PlaybookNode) -> Optional[str]:
        """Why ``node`` cannot execute, or ``None`` when it can."""
        if node.node_type in NOT_IMPLEMENTED_NODE_TYPES:
            return NOT_IMPLEMENTED_NODE_TYPES[node.node_type]
        if node.node_type not in self.node_executors:
            return f"unknown node type {node.node_type!r}"
        config = self._config(node)
        if config.get("__invalid__"):
            return "node config is not a JSON object"
        if node.node_type == NodeType.ACTION.value:
            action_type = config.get("action_type")
            if not action_type:
                return "action node has no action_type configured"
            if action_type not in ACTION_NODE_TYPES:
                return f"action_type {action_type!r} is not supported (supported: {sorted(ACTION_NODE_TYPES)})"
        elif node.node_type == NodeType.CONDITION.value:
            if not config.get("expression"):
                return "condition node has no expression"
        elif node.node_type == NodeType.ENRICHMENT.value:
            if str(config.get("enrichment_type") or "").lower() not in ENRICHMENT_TYPES:
                return f"enrichment_type must be one of {sorted(ENRICHMENT_TYPES)}"
        elif node.node_type == NodeType.NOTIFICATION.value:
            if str(config.get("channel") or "").lower() not in ("email", "slack", "teams"):
                return "notification channel must be email, slack or teams"
            if not config.get("message"):
                return "notification node has no message"
        elif node.node_type == NodeType.API_CALL.value:
            if not config.get("installation_id") or not config.get("url"):
                return "api_call needs installation_id (an installed integration) and url"
        elif node.node_type == NodeType.VARIABLE_SET.value:
            if not config.get("variable_name"):
                return "variable_set node has no variable_name"
        return None

    def node_is_privileged(self, node: PlaybookNode) -> bool:
        """True when ``node`` can change something outside PySOAR (admin-only to run).

        Classified by capability and fail closed: api_call (outbound HTTP),
        agent_command, containment and any integration action that is not on
        the read-only allowlist. An unparseable action node is privileged.
        """
        from src.services.playbook_engine import is_privileged_step

        if node.node_type == NodeType.API_CALL.value:
            return True
        if node.node_type != NodeType.ACTION.value:
            return False
        config = self._config(node)
        if config.get("__invalid__"):
            return True
        params = config.get("params") if isinstance(config.get("params"), dict) else {}
        return is_privileged_step(str(config.get("action_type") or ""), params)

    def privileged_nodes(self, playbook: VisualPlaybook) -> list[str]:
        """node_ids of every privileged node in ``playbook``."""
        return [n.node_id for n in playbook.nodes if self.node_is_privileged(n)]

    def unsupported_nodes(self, playbook: VisualPlaybook) -> list[dict[str, str]]:
        """Every node that cannot execute, with the reason (empty when the playbook can run)."""
        problems = []
        for node in playbook.nodes:
            reason = self.node_problem(node)
            if reason:
                problems.append({"node_id": node.node_id, "node_type": node.node_type, "reason": reason})
        return problems

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    def _runtime(self, execution: VisualPlaybookExecution) -> Any:
        from src.services.playbook_engine import StepRuntime

        if self.db is None:
            raise RuntimeError("this node needs a database session (PlaybookExecutionEngine(db))")
        return StepRuntime(
            db=self.db,
            organization_id=execution.organization_id,
            execution_id=execution.id,
            actor=self.actor or f"system:playbook:{execution.id}",
            actor_user_id=self.actor_user_id,
        )

    async def execute_playbook(
        self,
        playbook: VisualPlaybook,
        trigger_event: Optional[dict] = None,
        variables: Optional[dict] = None,
        execution: Optional[VisualPlaybookExecution] = None,
    ) -> VisualPlaybookExecution:
        """Run ``playbook``; updates (or creates) ``execution`` and persists node executions."""
        started = datetime.now(timezone.utc)
        if execution is None:
            execution = VisualPlaybookExecution(
                playbook_id=playbook.id,
                organization_id=playbook.organization_id,
                trigger_event=json.dumps(trigger_event) if trigger_event else None,
                variables=json.dumps(variables or {}),
            )
            if self.db is not None:
                self.db.add(execution)
                await self.db.flush()
        execution.status = ExecutionStatus.RUNNING.value
        execution.started_at = started.isoformat()
        runtime_vars: dict[str, Any] = {**(trigger_event or {}), **(variables or {})}
        runtime_vars["trigger_event"] = trigger_event or {}
        node_statuses: list[str] = []
        execution_path: list[str] = []
        failure: Optional[str] = None

        trigger_nodes = [n for n in playbook.nodes if n.node_type == NodeType.TRIGGER.value]
        if not trigger_nodes:
            failure = "No trigger node found"
        current: Optional[PlaybookNode] = trigger_nodes[0] if trigger_nodes else None
        steps = 0
        while current is not None and failure is None:
            steps += 1
            if steps > MAX_NODE_STEPS:
                failure = f"Execution aborted after {MAX_NODE_STEPS} node steps (cycle?)"
                break
            execution.current_node_id = current.node_id
            node_exec, branch = await self.execute_node(current, execution, runtime_vars)
            execution_path.append(current.node_id)
            node_statuses.append(node_exec.status)
            runtime_vars[current.node_id] = safe_json_loads(node_exec.output_data, {}) or {}
            failed = node_exec.status in (NODE_FAILED, NODE_NOT_IMPLEMENTED)
            if failed and current.on_error != ErrorHandler.CONTINUE.value:
                failure = f"Node {current.node_id} ({current.display_name}) {node_exec.status}: {node_exec.error_message}"
                break
            current = self._get_next_node(playbook, current, node_exec.status, runtime_vars, branch)

        completed = datetime.now(timezone.utc)
        execution.completed_at = completed.isoformat()
        execution.duration_ms = int((completed - started).total_seconds() * 1000)
        execution.execution_path = json.dumps(execution_path)
        if failure:
            execution.status = ExecutionStatus.FAILED.value
            execution.error_message = failure
        elif all(s == NODE_COMPLETED for s in node_statuses):
            execution.status = ExecutionStatus.COMPLETED.value
        else:
            execution.status = RUN_PARTIAL
        if self.db is not None:
            await self.db.flush()
        return execution

    async def execute_node(
        self,
        node: PlaybookNode,
        execution: VisualPlaybookExecution,
        variables: dict,
    ) -> tuple[PlaybookNodeExecution, Optional[bool]]:
        """Execute one node; returns its persisted execution row and a condition branch."""
        started = datetime.now(timezone.utc)
        config = self._config(node)
        node_exec = PlaybookNodeExecution(
            execution_id=execution.id,
            organization_id=execution.organization_id,
            node_id=node.node_id,
            status=NodeExecutionStatus.RUNNING.value,
            started_at=started.isoformat(),
            input_data=json.dumps({k: v for k, v in config.items() if k != "__invalid__"}, default=str),
        )
        branch: Optional[bool] = None
        problem = self.node_problem(node)
        if problem:
            status, output, error = NODE_NOT_IMPLEMENTED, {}, problem
        else:
            try:
                status, output, error = await asyncio.wait_for(
                    self.node_executors[node.node_type](config, variables, execution),
                    timeout=max(1, int(node.timeout_seconds or 300)),
                )
                if node.node_type == NodeType.CONDITION.value:
                    branch = bool(output.get("result"))
            except asyncio.TimeoutError:
                status, output, error = NODE_FAILED, {}, f"node timed out after {node.timeout_seconds}s"
            except Exception as exc:  # a crashing node is a failed node, never a silent success
                logger.error("visual_playbook_node_failed", node_id=node.node_id, error=str(exc))
                status, output, error = NODE_FAILED, {}, str(exc)
        finished = datetime.now(timezone.utc)
        node_exec.status = status
        node_exec.output_data = json.dumps(output, default=str)
        node_exec.error_message = error
        node_exec.completed_at = finished.isoformat()
        node_exec.duration_ms = int((finished - started).total_seconds() * 1000)
        if self.db is not None:
            self.db.add(node_exec)
            await self.db.flush()
        return node_exec, branch

    # ------------------------------------------------------------------
    # Node executors: (config, variables, execution) -> (status, output, error)
    # ------------------------------------------------------------------

    def _resolve(self, value: Any, variables: dict) -> Any:
        if isinstance(value, str) and value.startswith("$."):
            return self._get_json_path(variables, value)
        if isinstance(value, dict):
            return {k: self._resolve(v, variables) for k, v in value.items()}
        return value

    async def _classic_step(self, action: str, params: dict, variables: dict, execution: VisualPlaybookExecution) -> tuple:
        from src.services.playbook_engine import run_step_in_runtime

        context = {k: v for k, v in variables.items() if isinstance(v, (str, int, float, bool))}
        context["organization_id"] = execution.organization_id
        context["playbook_execution_id"] = execution.id
        result = await run_step_in_runtime(self._runtime(execution), action, self._resolve(params, variables), context)
        status = result.get("status") or (NODE_COMPLETED if result.get("success") else NODE_FAILED)
        if status not in (
            NODE_COMPLETED, NODE_FAILED, NODE_AWAITING_INTEGRATION, NODE_QUEUED_FOR_APPROVAL, NODE_MANUAL_REQUIRED,
        ):
            status = NODE_FAILED
        error = result.get("error") or (result.get("missing_dependency") if status == NODE_AWAITING_INTEGRATION else None)
        return status, result, error

    async def _trigger_executor(self, config: dict, variables: dict, execution: VisualPlaybookExecution) -> tuple:
        return NODE_COMPLETED, {"triggered": True, "trigger_event": variables.get("trigger_event", {})}, None

    async def _action_executor(self, config: dict, variables: dict, execution: VisualPlaybookExecution) -> tuple:
        action_type = config["action_type"]
        params = config.get("params") or {}
        if action_type == "agent_command":
            return await self._agent_command(params, variables, execution)
        return await self._classic_step(action_type, params, variables, execution)

    async def _agent_command(self, params: dict, variables: dict, execution: VisualPlaybookExecution) -> tuple:
        """Queue an allowlisted command on one of the organisation's enrolled agents (no approval override)."""
        from sqlalchemy import select

        from src.agents.models import EndpointAgent
        from src.agents.service import AgentService, AgentServiceError
        from src.models.audit import AuditLog

        if self.db is None:
            raise RuntimeError("agent_command needs a database session")
        params = self._resolve(params, variables)
        agent_id, action = params.get("agent_id"), params.get("action")
        if not agent_id or not action:
            return NODE_FAILED, {}, "agent_command needs agent_id and action"
        agent = (await self.db.execute(
            select(EndpointAgent).where(EndpointAgent.id == agent_id, EndpointAgent.organization_id == execution.organization_id)
        )).scalar_one_or_none()
        if agent is None:
            return NODE_FAILED, {}, f"endpoint agent {agent_id} not found in this organisation"
        try:
            cmd = await AgentService(self.db).issue_command(
                agent=agent, action=str(action), payload=params.get("payload") or {}, issued_by=self.actor_user_id,
            )
        except AgentServiceError as exc:
            status, output, error = NODE_FAILED, {"agent_id": agent.id}, str(exc)
        else:
            status = NODE_QUEUED_FOR_APPROVAL if cmd.status == "awaiting_approval" else NODE_COMPLETED
            output, error = {"agent_id": agent.id, "command_id": cmd.id, "command_status": cmd.status}, None
        self.db.add(AuditLog(
            user_id=self.actor_user_id, organization_id=execution.organization_id, action="playbook_agent_command",
            resource_type="visual_playbook_execution", resource_id=execution.id,
            description=f"agent_command {action} on {agent.hostname}: {status}",
            new_value=json.dumps({**output, "action": action, "actor": self.actor or f"system:playbook:{execution.id}"}),
            success=status != NODE_FAILED, error_message=error,
        ))
        await self.db.flush()
        return status, output, error

    async def _condition_executor(self, config: dict, variables: dict, execution: VisualPlaybookExecution) -> tuple:
        expression = config["expression"]
        result = self.evaluate_condition(expression, variables)
        return NODE_COMPLETED, {"condition": expression, "result": result}, None

    async def _transform_executor(self, config: dict, variables: dict, execution: VisualPlaybookExecution) -> tuple:
        mapping = config.get("mapping", {}) or {}
        transformed = {key: self._get_json_path(variables, path) for key, path in mapping.items()}
        variables.update(transformed)
        return NODE_COMPLETED, transformed, None

    async def _delay_executor(self, config: dict, variables: dict, execution: VisualPlaybookExecution) -> tuple:
        try:
            seconds = max(0.0, min(float(config.get("duration_seconds", 1)), MAX_DELAY_SECONDS))
        except (TypeError, ValueError):
            return NODE_FAILED, {}, "duration_seconds must be a number"
        await asyncio.sleep(seconds)
        return NODE_COMPLETED, {"delayed_seconds": seconds}, None

    async def _enrichment_executor(self, config: dict, variables: dict, execution: VisualPlaybookExecution) -> tuple:
        kind = str(config["enrichment_type"]).lower()
        value = self._resolve(config.get("value"), variables)
        if value is None and config.get("value_path"):
            value = self._get_json_path(variables, str(config["value_path"]))
        return await self._classic_step("enrich", {"value": str(value or ""), "type": kind}, variables, execution)

    async def _notification_executor(self, config: dict, variables: dict, execution: VisualPlaybookExecution) -> tuple:
        params = {k: v for k, v in config.items() if k in ("channel", "message", "recipients", "subject", "channel_name")}
        return await self._classic_step("notify", params, variables, execution)

    async def _variable_set_executor(self, config: dict, variables: dict, execution: VisualPlaybookExecution) -> tuple:
        var_name = config["variable_name"]
        var_value = self._resolve(config.get("variable_value"), variables)
        variables[var_name] = var_value
        return NODE_COMPLETED, {"variable": var_name, "value": var_value}, None

    async def _api_call_executor(self, config: dict, variables: dict, execution: VisualPlaybookExecution) -> tuple:
        params = {k: v for k, v in config.items() if k in ("installation_id", "url", "method", "headers", "body", "params", "timeout_seconds")}
        return await self._classic_step("http_request", params, variables, execution)

    def evaluate_condition(self, expression: str, variables: dict) -> bool:
        """Evaluate a condition expression (AND / OR / NOT and comparisons).

        An expression without a recognised comparison is False, never True.
        """
        if not expression:
            return False

        expression = expression.strip()

        if expression.startswith("NOT "):
            return not self.evaluate_condition(expression[4:], variables)

        if " OR " in expression:
            parts = expression.split(" OR ")
            return any(self.evaluate_condition(p.strip(), variables) for p in parts)

        if " AND " in expression:
            parts = expression.split(" AND ")
            return all(self.evaluate_condition(p.strip(), variables) for p in parts)

        for op in ["==", "!=", ">=", "<=", ">", "<", " contains ", " matches "]:
            if op in expression:
                parts = expression.split(op)
                if len(parts) == 2:
                    left = self._resolve_value(parts[0].strip(), variables)
                    right = self._resolve_value(parts[1].strip(), variables)
                    try:
                        if op == "==":
                            return left == right
                        if op == "!=":
                            return left != right
                        if op == ">=":
                            return left >= right
                        if op == "<=":
                            return left <= right
                        if op == ">":
                            return left > right
                        if op == "<":
                            return left < right
                    except TypeError:
                        return False
                    if op == " contains ":
                        return str(right) in str(left)
                    if op == " matches ":
                        return bool(re.search(str(right), str(left)))

        return False

    def _resolve_value(self, value_str: str, variables: dict) -> Any:
        """Resolve a value string to actual value"""
        value_str = value_str.strip()

        if value_str.startswith("$."):
            return self._get_json_path(variables, value_str)

        if value_str in variables:
            return variables[value_str]

        try:
            return json.loads(value_str)
        except (json.JSONDecodeError, ValueError):
            return value_str.strip("'\"")

    def _get_json_path(self, data: dict, path: str) -> Any:
        """Get value from JSON path"""
        if path.startswith("$."):
            path = path[2:]

        current: Any = data
        for part in path.split("."):
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
        branch: Optional[bool] = None,
    ) -> Optional[PlaybookNode]:
        """Next node: success edges after a completed node (or a true condition),
        failure edges after a failed node (or a false condition), always edges either way."""
        outgoing_edges = sorted(
            (e for e in playbook.edges if e.source_node_id == current_node.node_id),
            key=lambda e: e.priority, reverse=True,
        )
        if branch is not None:
            took_success = branch
        else:
            took_success = node_status != NODE_FAILED and node_status != NODE_NOT_IMPLEMENTED
        for edge in outgoing_edges:
            if edge.edge_type in (EdgeType.SUCCESS.value, EdgeType.CONDITIONAL.value) and not took_success:
                continue
            if edge.edge_type in (EdgeType.FAILURE.value, EdgeType.ERROR.value) and took_success:
                continue
            if edge.edge_type == EdgeType.TIMEOUT.value:
                continue
            if edge.condition_expression and not self.evaluate_condition(edge.condition_expression, variables):
                continue
            return next((n for n in playbook.nodes if n.node_id == edge.target_node_id), None)
        return None


async def run_visual_execution(
    db: AsyncSession, execution_id: str,
) -> VisualPlaybookExecution:
    """Drive one persisted VisualPlaybookExecution through the engine (worker and tests)."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from src.models.user import User

    execution = (await db.execute(
        select(VisualPlaybookExecution).where(VisualPlaybookExecution.id == execution_id)
    )).scalar_one_or_none()
    if execution is None:
        raise ValueError(f"Visual playbook execution {execution_id} not found")
    playbook = (await db.execute(
        select(VisualPlaybook)
        .options(selectinload(VisualPlaybook.nodes), selectinload(VisualPlaybook.edges))
        .where(VisualPlaybook.id == execution.playbook_id, VisualPlaybook.organization_id == execution.organization_id)
        .execution_options(populate_existing=True)  # the graph as stored now, not a cached copy
    )).scalar_one_or_none()
    if playbook is None:
        execution.status = ExecutionStatus.FAILED.value
        execution.error_message = "playbook not found in the execution's organisation"
        execution.completed_at = datetime.now(timezone.utc).isoformat()
        await db.flush()
        return execution

    actor_user_id = None
    actor_is_admin = False
    if execution.triggered_by:
        row = (await db.execute(
            select(User.id, User.role, User.is_superuser)
            .where(User.id == execution.triggered_by, User.organization_id == execution.organization_id)
        )).first()
        if row is not None:
            actor_user_id = row.id
            actor_is_admin = bool(row.is_superuser) or row.role == "admin"
    engine = PlaybookExecutionEngine(db, actor=actor_user_id, actor_user_id=actor_user_id)

    # Re-check privilege at run time against the role recorded at dispatch
    # (and the user's current role): a playbook edited after dispatch, or a
    # run with no admin behind it, never reaches a privileged node.
    privileged = engine.privileged_nodes(playbook)
    if privileged and not (execution.triggered_by_role == "admin" and actor_is_admin):
        now = datetime.now(timezone.utc).isoformat()
        reason = (
            f"forbidden_privileged_node: node(s) {', '.join(privileged)} need an admin; "
            f"run triggered with role {execution.triggered_by_role or 'none'}"
        )
        for node_id in privileged:
            db.add(PlaybookNodeExecution(
                execution_id=execution.id, organization_id=execution.organization_id, node_id=node_id,
                status=NODE_FORBIDDEN, started_at=now, completed_at=now, duration_ms=0,
                error_message="forbidden_privileged_node", output_data=json.dumps({"error": "forbidden_privileged_node"}),
            ))
        execution.status = ExecutionStatus.FAILED.value
        execution.error_message = reason
        execution.started_at = execution.started_at or now
        execution.completed_at = now
        execution.duration_ms = 0
        execution.execution_path = json.dumps([])
        await db.flush()
        logger.warning("visual_playbook_privileged_node_refused", execution_id=execution.id, nodes=privileged)
        return execution

    await engine.execute_playbook(
        playbook,
        trigger_event=safe_json_loads(execution.trigger_event, None),
        variables=safe_json_loads(execution.variables, None),
        execution=execution,
    )
    playbook.execution_count = (playbook.execution_count or 0) + 1
    playbook.last_executed = execution.completed_at
    await db.flush()
    return execution


class TemplateLibrary:
    """Built-in playbook templates.

    Only templates whose every node is configured and executable ship here.
    The 13 name-only templates (ransomware_ir, brute_force_response, ...) had
    zero nodes and were removed rather than shown as if they did something.
    """

    @staticmethod
    def get_templates() -> dict[str, dict]:
        """Get all available templates"""
        return {
            "phishing_response": TemplateLibrary.phishing_response_template(),
            "malware_triage": TemplateLibrary.malware_triage_template(),
        }

    @staticmethod
    def phishing_response_template() -> dict:
        """Phishing response: enrich the sender domain, then tell the SOC on Slack."""
        return {
            "name": "Phishing Response",
            "description": (
                "Enrich the reported sender domain (trigger field sender_domain) with threat intel "
                "and post the result to the organisation's Slack webhook."
            ),
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
                    "display_name": "Enrich Sender Domain",
                    "position_x": 100,
                    "position_y": 150,
                    "config": {"enrichment_type": "domain", "value_path": "$.sender_domain"},
                },
                {
                    "node_id": "notify_1",
                    "node_type": "notification",
                    "display_name": "Notify SOC",
                    "position_x": 100,
                    "position_y": 250,
                    "config": {
                        "channel": "slack",
                        "message": "Phishing report: sender domain {{sender_domain}} enriched; review the run for details.",
                    },
                },
            ],
            "edges": [
                {"source_node_id": "trigger_1", "target_node_id": "enrich_1", "edge_type": "success"},
                {"source_node_id": "enrich_1", "target_node_id": "notify_1", "edge_type": "success"},
            ],
        }

    @staticmethod
    def malware_triage_template() -> dict:
        """Malware triage: enrich the file hash, then email the team."""
        return {
            "name": "Malware Triage",
            "description": (
                "Look up the alert's file hash (trigger field file_hash) in threat intel and email "
                "the address in trigger field notify_email."
            ),
            "category": "threat_hunting",
            "trigger_type": "alert",
            "nodes": [
                {"node_id": "t1", "node_type": "trigger", "display_name": "Malware Alert", "position_x": 0, "position_y": 0},
                {
                    "node_id": "a1", "node_type": "enrichment", "display_name": "Hash Lookup", "position_x": 0, "position_y": 100,
                    "config": {"enrichment_type": "hash", "value_path": "$.file_hash"},
                },
                {
                    "node_id": "n1", "node_type": "notification", "display_name": "Alert Team", "position_x": 0, "position_y": 200,
                    "config": {
                        "channel": "email", "recipients": "$.notify_email", "subject": "Malware triage: {{file_hash}}",
                        "message": "Threat-intel lookup finished for {{file_hash}}; review the run for details.",
                    },
                },
            ],
            "edges": [
                {"source_node_id": "t1", "target_node_id": "a1", "edge_type": "success"},
                {"source_node_id": "a1", "target_node_id": "n1", "edge_type": "success"},
            ],
        }
