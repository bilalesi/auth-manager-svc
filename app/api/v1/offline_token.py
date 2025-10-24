"""Offline token consent and callback endpoints."""

import secrets
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Query, status
from keycloak import urls_patterns

from app.core.errors import ErrorKeys
from app.core.exceptions import KeycloakError
from app.core.guards import auth_error_guard, invariant_guard
from app.core.logging import get_logger
from app.core.security import ValidatedTokenDep
from app.db.models import TokenType
from app.dependencies import KeycloakDep, StateTokenDep, TokenVaultServiceDep
from app.models.api import Ok
from app.models.response import OfflineConsentResult, OfflineTokenResult

logger = get_logger(__name__)

router = APIRouter(prefix="/offline-token")


@router.get(
    "/callback",
    response_model=Ok[OfflineTokenResult],
    status_code=status.HTTP_200_OK,
    summary="Offline token OAuth callback",
    description="Handles the OAuth callback after user consent, exchanges authorization code for tokens, and stores the offline token.",
)
async def offline_token_callback(
    keycloak: KeycloakDep,
    ack_state_service: StateTokenDep,
    vault_service: TokenVaultServiceDep,
    code: str = Query(..., description="Authorization code from Keycloak"),
    state: str = Query(..., description="Ack state token for validation"),
    error: Optional[str] = Query(None, description="Error code from Keycloak"),
    error_description: Optional[str] = Query(None, description="Error description from Keycloak"),
) -> Ok[OfflineTokenResult]:
    """Handle OAuth callback after user consent for offline access.

    This endpoint receives the OAuth callback from Keycloak after the user
    grants consent for offline access. It validates the state token, exchanges
    the authorization code for tokens, encrypts and stores the offline token,
    and returns the persistent token ID.


    Args:
        code: Authorization code from OAuth callback (required)
        state: State token containing user_id and session_state_id (required)
        error: Error parameter if Keycloak returned an error
        keycloak: Keycloak service dependency
        ack_state_service: State token service dependency
        vault_service: Token vault service dependency

    Returns:
        OkResponse containing OfflineTokenResponse with persistent_token_id

    Raises:
        InvalidStateTokenError: If state token is invalid or expired (400)
        KeycloakError: If Keycloak returns an error or code exchange fails (400/500)
    """

    with invariant_guard(
        None,
        lambda _: error or error_description,
        KeycloakError(
            str(error or error_description),
            ErrorKeys.keycloak_callback_error.name,
        ),
    ):
        with auth_error_guard(
            None,
            "Ack state was tempered",
        ):
            state_payload = ack_state_service.parse_ack_state(state)

    with auth_error_guard(
        None,
        "Could not generate offline token",
    ):
        token_response = await keycloak.exchange_code_for_token(
            code=code,
            redirect_uri=keycloak.settings.consent_redirect_uri,
        )

    with invariant_guard(
        token_response,
        lambda e: e.refresh_token is None,
        KeycloakError(
            "No refresh token received from Keycloak",
        ),
    ):
        user_id = UUID(state_payload.user_id)
        stored_entry = await vault_service.store(
            user_id=user_id,
            token=token_response.refresh_token,
            token_type=TokenType.OFFLINE,
            session_state_id=state_payload.session_state_id,
            attributes=None,
        )

        return Ok(
            data=OfflineTokenResult(
                persistent_token_id=stored_entry.id,
                session_state_id=state_payload.session_state_id,
            )
        )


@router.get(
    "",
    response_model=Ok[OfflineConsentResult],
    status_code=status.HTTP_200_OK,
    summary="Request offline token consent",
    description="Initiates the offline token consent flow by generating a Keycloak authorization url.",
)
async def request_offline_token_consent(
    validated_token: ValidatedTokenDep,
    keycloak: KeycloakDep,
    state_token_service: StateTokenDep,
) -> Ok[OfflineConsentResult]:
    """Request user consent for offline access.

    This endpoint validates the access token, extracts user information,
    generates a state token, and constructs a Keycloak authorization URL
    with offline_access scope for user consent.

    Args:
        validated_token: Validated token with user information (validated by dependency)
        keycloak: Keycloak service dependency
        state_token_service: State token service dependency

    Returns:
        OkResponse containing OfflineConsentResponse with consent URL

    Raises:
        UnauthorizedError: If bearer token is missing or invalid
    """

    user_id = str(validated_token.user_id)
    session_state_id = validated_token.session_state_id

    state_token = state_token_service.make_ack_state(
        user_id=user_id,
        session_state_id=session_state_id,
    )

    authorization_endpoint = f"{keycloak.settings.issuer}/realms/{keycloak.settings.realm}"
    auth_params = {
        "authorization-endpoint": f"{authorization_endpoint}/protocol/openid-connect/auth",
        "client-id": keycloak.settings.client_id,
        "redirect-uri": keycloak.settings.consent_redirect_uri,
        "scope": "openid profile email offline_access",
        "state": state_token,
        "nonce": secrets.token_urlsafe(32),
    }

    consent_url = urls_patterns.URL_AUTH.format(**auth_params)

    return Ok(
        data=OfflineConsentResult(
            consent_url=consent_url,
            session_state_id=session_state_id,
            message="Please visit the consent URL to authorize offline access",
        )
    )
