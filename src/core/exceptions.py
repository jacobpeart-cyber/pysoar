"""Custom exceptions for PySOAR"""

from typing import Any, Optional


class PySOARException(Exception):
    """Base exception for PySOAR"""

    def __init__(
        self,
        message: str = "An error occurred",
        details: Optional[dict[str, Any]] = None,
    ):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class AuthenticationError(PySOARException):
    """Raised when authentication fails"""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message)


class AuthorizationError(PySOARException):
    """Raised when authorization fails"""

    def __init__(self, message: str = "Access denied"):
        super().__init__(message)


class NotFoundError(PySOARException):
    """Raised when a resource is not found"""

    def __init__(self, resource: str, identifier: Any):
        super().__init__(
            message=f"{resource} not found",
            details={"resource": resource, "identifier": str(identifier)},
        )


class ValidationError(PySOARException):
    """Raised when validation fails"""

    def __init__(self, message: str = "Validation error", errors: Optional[list] = None):
        super().__init__(message, details={"errors": errors or []})


class IntegrationError(PySOARException):
    """Raised when an external integration fails"""

    def __init__(
        self,
        service: str,
        message: str = "Integration error",
        details: Optional[dict] = None,
    ):
        super().__init__(
            message=f"{service}: {message}",
            details={"service": service, **(details or {})},
        )


class PlaybookError(PySOARException):
    """Raised when playbook execution fails"""

    def __init__(
        self,
        playbook_id: str,
        message: str = "Playbook execution failed",
        step: Optional[str] = None,
    ):
        super().__init__(
            message=message,
            details={"playbook_id": playbook_id, "step": step},
        )


class RateLimitError(PySOARException):
    """Raised when rate limit is exceeded"""

    def __init__(self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None):
        super().__init__(message, details={"retry_after": retry_after})
