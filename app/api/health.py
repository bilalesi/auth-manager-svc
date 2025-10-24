"""Health check endpoints."""

from fastapi import APIRouter, status
from pydantic import BaseModel
from sqlalchemy import text
from starlette.responses import Response

from app.config import get_settings
from app.core.logging import get_logger
from app.dependencies import KeycloakDep, SessionDep
from app.models.api import Err, Ok

logger = get_logger(__name__)

router = APIRouter(tags=["service"])
config = get_settings()


class HealthStatus(BaseModel):
    """Health status response model."""

    status: str
    version: str
    service: str


class ReadinessStatus(BaseModel):
    """Readiness status response model."""

    app_name: str
    app_version: str
    database_status: str


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check() -> str:
    """Basic health check endpoint."""
    logger.debug("health_check")
    return "OK"


@router.get("/health/ready")
async def readiness_check(db: SessionDep) -> Response:
    """Readiness check endpoint with database connectivity verification."""

    logger.debug("readiness_check")

    try:
        result = await db.execute(text("SELECT 1"))
        result.scalar_one()

        response_data = Ok(
            data=ReadinessStatus(
                app_name=config.app_name,
                app_version=config.app_version,
                database_status="connected",
            )
        )

        return Response(
            content=response_data.model_dump_json(),
            status_code=status.HTTP_200_OK,
            media_type="application/json",
        )

    except Exception as e:
        response_data = Err(
            error="Readiness check failed",
            code="readiness_check_failed",
            reason=str(e),
            details={"database": "disconnected"},
        )
        logger.error(
            "readiness_check_failed", error=str(e), response_data=response_data.model_dump_json()
        )

        return Response(
            content=response_data.model_dump_json(),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            media_type="application/json",
        )


@router.get(
    "/version",
)
async def root(db: SessionDep, kc: KeycloakDep) -> Ok[dict]:
    """Version endpoint providing basic service information."""
    result = await db.execute(text("SELECT version();"))
    database_version = result.scalar_one()

    return Ok(
        data={
            "app_name": config.app_name,
            "app_version": config.app_version,
            "database_version": database_version,
        }
    )
