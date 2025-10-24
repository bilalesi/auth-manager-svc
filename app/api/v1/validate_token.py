"""Token validation endpoint."""

from fastapi import APIRouter, status

from app.core.exceptions import TokenNotActiveError
from app.core.guards import invariant_guard
from app.core.logging import get_logger
from app.core.security import BearerToken
from app.dependencies import KeycloakDep
from app.models.api import Ok
from app.models.response import ValidationResponse

logger = get_logger(__name__)

router = APIRouter()


@router.get(
    "/validate-token",
    response_model=Ok[ValidationResponse],
    status_code=status.HTTP_200_OK,
    summary="Validate access token",
    description="Validates an access token by introspecting it with Keycloak.",
)
async def validate_token(
    token: BearerToken,
    keycloak: KeycloakDep,
) -> Ok[ValidationResponse]:
    """Validate an access token via Keycloak introspection."""

    introspection_result = await keycloak.introspect_token(token)

    with invariant_guard(
        introspection_result,
        lambda e: not e.active,
        TokenNotActiveError("Token is not active"),
    ):
        pass

    return Ok(data=ValidationResponse(valid=True))
