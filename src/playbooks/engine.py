"""Playbook execution engine"""

import json
from datetime import datetime, timezone
from typing import Any, Optional

from src.core.exceptions import PlaybookError
from src.core.logging import get_logger
from src.models.playbook import ExecutionStatus, PlaybookExecution
from src.playbooks.actions import get_action

logger = get_logger(__name__)


class PlaybookEngine:
    """Engine for executing playbooks"""

    def __init__(self):
        self.current_execution: Optional[PlaybookExecution] = None
        self.context: dict[str, Any] = {}
        self.step_results: list[dict[str, Any]] = []

    async def execute(
        self,
        execution: PlaybookExecution,
        steps: list[dict[str, Any]],
        input_data: Optional[dict[str, Any]] = None,
    ) -> PlaybookExecution:
        """Execute a playbook"""
        self.current_execution = execution
        self.context = input_data or {}
        self.step_results = []

        execution.status = ExecutionStatus.RUNNING.value
        execution.started_at = datetime.now(timezone.utc).isoformat()
        execution.total_steps = len(steps)

        logger.info(
            "Starting playbook execution",
            execution_id=execution.id,
            playbook_id=execution.playbook_id,
            total_steps=len(steps),
        )

        try:
            # Build step lookup for navigation
            step_lookup = {step["id"]: step for step in steps}
            current_step_id = steps[0]["id"] if steps else None
            step_index = 0

            while current_step_id and step_index < len(steps) * 2:  # Prevent infinite loops
                step = step_lookup.get(current_step_id)
                if not step:
                    raise PlaybookError(
                        playbook_id=execution.playbook_id,
                        message=f"Step not found: {current_step_id}",
                        step=current_step_id,
                    )

                execution.current_step = step_index
                step_index += 1

                # Execute the step
                result = await self._execute_step(step)
                self.step_results.append(result)

                # Update context with step results
                self.context[f"step_{step['id']}_result"] = result
                if result.get("success"):
                    for key, value in result.items():
                        if key not in ["success", "error"]:
                            self.context[key] = value

                # Determine next step
                if result.get("success"):
                    # Check if this is a conditional action
                    if step.get("action") == "conditional":
                        if result.get("condition_met"):
                            current_step_id = step.get("on_success")
                        else:
                            current_step_id = step.get("on_failure")
                    else:
                        current_step_id = step.get("on_success")
                else:
                    if step.get("continue_on_error"):
                        current_step_id = step.get("on_success")
                    else:
                        current_step_id = step.get("on_failure")
                        if not current_step_id:
                            # No failure handler, stop execution
                            raise PlaybookError(
                                playbook_id=execution.playbook_id,
                                message=f"Step failed: {result.get('error', 'Unknown error')}",
                                step=step["id"],
                            )

            # Execution completed successfully
            execution.status = ExecutionStatus.COMPLETED.value
            execution.completed_at = datetime.now(timezone.utc).isoformat()
            execution.output_data = json.dumps(self.context)
            execution.step_results = json.dumps(self.step_results)

            logger.info(
                "Playbook execution completed",
                execution_id=execution.id,
                steps_executed=len(self.step_results),
            )

        except PlaybookError as e:
            execution.status = ExecutionStatus.FAILED.value
            execution.error_message = str(e)
            execution.error_step = execution.current_step
            execution.completed_at = datetime.now(timezone.utc).isoformat()
            execution.step_results = json.dumps(self.step_results)

            logger.error(
                "Playbook execution failed",
                execution_id=execution.id,
                error=str(e),
                step=e.details.get("step"),
            )

        except Exception as e:
            execution.status = ExecutionStatus.FAILED.value
            execution.error_message = str(e)
            execution.completed_at = datetime.now(timezone.utc).isoformat()
            execution.step_results = json.dumps(self.step_results)

            logger.error(
                "Playbook execution error",
                execution_id=execution.id,
                error=str(e),
            )

        return execution

    async def _execute_step(self, step: dict[str, Any]) -> dict[str, Any]:
        """Execute a single playbook step"""
        step_id = step["id"]
        step_name = step.get("name", step_id)
        action_name = step["action"]
        parameters = step.get("parameters", {})
        timeout = step.get("timeout_seconds", 300)

        logger.info(
            f"Executing step: {step_name}",
            step_id=step_id,
            action=action_name,
        )

        # Get the action
        action = get_action(action_name)
        if not action:
            return {
                "success": False,
                "error": f"Unknown action: {action_name}",
                "step_id": step_id,
                "step_name": step_name,
            }

        try:
            # Execute the action
            import asyncio

            result = await asyncio.wait_for(
                action.execute(parameters, self.context),
                timeout=timeout,
            )

            result["step_id"] = step_id
            result["step_name"] = step_name
            result["action"] = action_name
            result["executed_at"] = datetime.now(timezone.utc).isoformat()

            logger.info(
                f"Step completed: {step_name}",
                success=result.get("success"),
            )

            return result

        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": f"Step timed out after {timeout} seconds",
                "step_id": step_id,
                "step_name": step_name,
                "action": action_name,
            }

        except Exception as e:
            logger.error(f"Step failed: {step_name}", error=str(e))
            return {
                "success": False,
                "error": str(e),
                "step_id": step_id,
                "step_name": step_name,
                "action": action_name,
            }

    async def cancel(self) -> None:
        """Cancel the current execution"""
        if self.current_execution:
            self.current_execution.status = ExecutionStatus.CANCELLED.value
            self.current_execution.completed_at = datetime.now(timezone.utc).isoformat()
            logger.info(
                "Playbook execution cancelled",
                execution_id=self.current_execution.id,
            )


# Singleton engine instance
playbook_engine = PlaybookEngine()
