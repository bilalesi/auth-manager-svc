"""Access token endpoint."""

from fastapi import APIRouter, Query, status
from pydantic import UUID4

from app.core.guards import auth_error_guard
from app.core.logging import get_logger
from app.core.security import ValidatedTokenDep
from app.dependencies import KeycloakDep, TokenVaultServiceDep
from app.models.api import Ok
from app.models.response import AccessTokenResult

logger = get_logger(__name__)

router = APIRouter()


@router.post(
    "/access-token",
    response_model=Ok[AccessTokenResult],
    status_code=status.HTTP_200_OK,
    summary="Get fresh access token",
    description="Retrieves a fresh access token using a stored refresh/offline token.",
)
async def get_access_token(
    _: ValidatedTokenDep,
    keycloak: KeycloakDep,
    token_vault: TokenVaultServiceDep,
    id: UUID4 = Query(..., description="Persistent token ID (UUID)"),
) -> Ok[AccessTokenResult]:
    """Get a fresh access token using a stored refresh/offline token.

    This endpoint retrieves a stored refresh or offline token from the vault,
    decrypts it, and uses it to request a new access token from Keycloak.

    Token validation is handled by the ValidatedTokenDep dependency, which
    validates the bearer token and extracts user information before this
    endpoint handler is called.

    Args:
        validated_token: Validated token with user information (from ValidatedTokenDep)
        keycloak: Keycloak service dependency
        token_vault: Token vault service dependency
        id: Persistent token ID (UUID) from query parameter

    Returns:
        OkResponse containing AccessTokenResponse with new access token

    Raises:
        UnauthorizedError: If bearer token is missing or invalid (raised by ValidatedTokenDep)
        TokenNotFoundError: If persistent_token_id not found in vault
        KeycloakError: If token refresh fails
    """

    with auth_error_guard(
        None,
        "No data found for this persistent token id",
    ):
        entry, decrypted_token = await token_vault.retrieve_and_decrypt(id)

    with auth_error_guard(
        None,
        "Could not generate new access token",
    ):
        token_response = await keycloak.refresh_access_token(decrypted_token)

    if token_response.refresh_token:
        await token_vault.upsert_refresh_token(
            user_id=entry.user_id,
            token=token_response.refresh_token,
            session_state_id=token_response.session_state,
            attributes=entry.attributes,
        )

    return Ok(
        data=AccessTokenResult(
            access_token=token_response.access_token,
            expires_in=token_response.expires_in,
        )
    )
