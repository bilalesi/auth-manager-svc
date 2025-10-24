"""Refresh token ID endpoint."""

from fastapi import APIRouter, status

from app.core.exceptions import DatabaseError
from app.core.guards import auth_error_guard
from app.core.logging import get_logger
from app.core.security import ValidatedTokenDep
from app.dependencies import TokenVaultServiceDep
from app.models.api import Ok
from app.models.request import RefreshTokenPayload
from app.models.response import RefreshTokenIdResult

logger = get_logger(__name__)

router = APIRouter()


@router.post(
    "/refresh-token",
    response_model=Ok[RefreshTokenIdResult],
    status_code=status.HTTP_200_OK,
    summary="Generate new refresh token ID",
    description="Refreshes the user's refresh token and returns a new persistent token ID.",
)
async def store_refresh_token(
    validated_token: ValidatedTokenDep,
    vault: TokenVaultServiceDep,
    payload: RefreshTokenPayload,
) -> Ok[RefreshTokenIdResult]:
    """Generate a new refresh token ID.

    This endpoint retrieves the user's existing refresh token, uses it to
    refresh the access token with Keycloak, and stores the new refresh token
    with an upsert operation (ensuring only one refresh token per user).

    Args:
        validated_token: Validated token with user information
        vault: Token vault service dependency
        payload: Refresh token payload

    Returns:
        OkResponse containing RefreshTokenIdResponse with persistent_token_id

    Raises:
        UnauthorizedError: If bearer token is missing or invalid
        TokenNotFoundError: If no token found
        TokenNotFoundError: If no active refresh token found
        KeycloakError: If refresh token generation fails
    """

    user_id = validated_token.user_id
    session_id = validated_token.session_state_id

    with auth_error_guard(
        DatabaseError,
        "Inserting new refresh token failed",
    ):
        new_token_id = await vault.upsert_refresh_token(
            user_id=user_id,
            token=payload.refresh_token,
            session_state_id=session_id,
        )

    return Ok(
        data=RefreshTokenIdResult(
            persistent_token_id=new_token_id,
        )
    )
