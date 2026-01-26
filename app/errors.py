"""
Unified error handling and response format.

All API errors return:
{
    "error": {
        "code": "ERROR_CODE",
        "message": "Human-readable message",
        "details": {}
    }
}
"""
from typing import Any, Optional
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = {}


class ErrorResponse(BaseModel):
    error: ErrorDetail


# Error codes
class ErrorCode:
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    AUTH_FAILED = "AUTH_FAILED"
    NOT_FOUND = "NOT_FOUND"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    NOTEBOOKLM_ERROR = "NOTEBOOKLM_ERROR"
    MINIO_ERROR = "MINIO_ERROR"
    JOB_FAILED = "JOB_FAILED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"


class APIError(Exception):
    """Base API error with structured response."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        details: Optional[dict] = None,
    ):
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(message)

    def to_response(self) -> JSONResponse:
        return JSONResponse(
            status_code=self.status_code,
            content={
                "error": {
                    "code": self.code,
                    "message": self.message,
                    "details": self.details,
                }
            },
        )


# Convenience error classes
class NotAuthenticatedError(APIError):
    def __init__(self, message: str = "Upload storage_state.json at /auth"):
        super().__init__(
            code=ErrorCode.NOT_AUTHENTICATED,
            message=message,
            status_code=503,
        )


class NotFoundError(APIError):
    def __init__(self, resource: str, resource_id: str):
        super().__init__(
            code=ErrorCode.NOT_FOUND,
            message=f"{resource} not found: {resource_id}",
            status_code=404,
            details={"resource": resource, "id": resource_id},
        )


class ValidationError(APIError):
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(
            code=ErrorCode.VALIDATION_ERROR,
            message=message,
            status_code=400,
            details=details or {},
        )


class NotebookLMError(APIError):
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(
            code=ErrorCode.NOTEBOOKLM_ERROR,
            message=message,
            status_code=502,
            details=details or {},
        )


class MinIOError(APIError):
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(
            code=ErrorCode.MINIO_ERROR,
            message=message,
            status_code=502,
            details=details or {},
        )


class IdempotencyConflictError(APIError):
    def __init__(self, existing_job_id: str):
        super().__init__(
            code=ErrorCode.IDEMPOTENCY_CONFLICT,
            message="Request with this idempotency key already exists",
            status_code=409,
            details={"existing_job_id": existing_job_id},
        )


def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    """Handler for APIError exceptions."""
    return exc.to_response()


def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Convert HTTPException to unified format."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": "HTTP_ERROR",
                "message": exc.detail,
                "details": {},
            }
        },
    )


def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handler for unexpected exceptions."""
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": ErrorCode.INTERNAL_ERROR,
                "message": "Internal server error",
                "details": {},  # Don't expose internal details
            }
        },
    )
