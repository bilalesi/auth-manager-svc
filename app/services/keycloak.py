"""Keycloak service using python-keycloak SDK."""

import httpx
from keycloak import KeycloakAdmin, KeycloakOpenID, KeycloakPostError

from app.config import KeycloakSettings
from app.core.exceptions import KeycloakError
from app.models.domain import KeycloakTokenResponse, TokenIntrospection


class KeycloakSDKClient:
    """Keycloak SDK client wrapper."""

    def __init__(self, settings: KeycloakSettings) -> None:
        self.settings = settings
        self._openid_client: KeycloakOpenID | None = None
        self._admin_client: KeycloakAdmin | None = None

    @property
    def openid(self) -> KeycloakOpenID:
        """Get or create OpenID client."""
        if self._openid_client is None:
            self._openid_client = KeycloakOpenID(
                server_url=f"{self.settings.issuer}/",
                client_id=self.settings.client_id,
                realm_name=self.settings.realm,
                client_secret_key=self.settings.client_secret,
                verify=True,
            )
        return self._openid_client

    @property
    def admin(self) -> KeycloakAdmin:
        """Get or create Admin client."""
        if self._admin_client is None:
            self._admin_client = KeycloakAdmin(
                server_url=f"{self.settings.issuer}/",
                client_id=self.settings.client_id,
                realm_name=self.settings.realm,
                client_secret_key=self.settings.client_secret,
            )
        return self._admin_client


class KeycloakService:
    """Service for interacting with Keycloak using python-keycloak SDK."""

    def __init__(self, settings: KeycloakSettings) -> None:
        self.settings = settings
        self.client = KeycloakSDKClient(settings)
        self.net = httpx.AsyncClient(timeout=30.0)

    async def refresh_access_token(self, refresh_token: str) -> KeycloakTokenResponse:
        """Refresh access token using refresh token."""
        try:
            result = await self.client.openid.a_refresh_token(refresh_token)
            return KeycloakTokenResponse(**result)
        except KeycloakPostError as e:
            raise KeycloakError(
                "Token refresh failed",
                details={
                    "code": e.response_code,
                    "body": e.response_body,
                },
            ) from e

    async def request_offline_token(self, offline_token: str) -> KeycloakTokenResponse:
        """Request offline token with offline_access scope."""
        try:
            result = await self.client.openid.a_refresh_token(
                grant_type="refresh_token",
                refresh_token=offline_token,
            )
            return KeycloakTokenResponse(**result)
        except KeycloakPostError as e:
            raise KeycloakError(
                "Offline token request failed",
                details={
                    "code": e.response_code,
                    "body": e.response_body,
                },
            ) from e

    async def introspect_token(self, token: str) -> TokenIntrospection:
        """Introspect token to check if it's active."""
        try:
            result = await self.client.openid.a_introspect(token)
            return TokenIntrospection(**result)
        except KeycloakPostError as e:
            raise KeycloakError(
                "Token introspection failed",
                details={
                    "code": e.response_code,
                    "body": e.response_body,
                },
            ) from e

    async def revoke_session(self, session_id: str) -> None:
        """Revoke Keycloak session using admin API."""

        url = f"{self.settings.issuer}/admin/realms/{self.settings.realm}/sessions/{session_id}?isOffline=true"
        admin_token = await self._get_admin_token()
        headers = {"Authorization": f"Bearer {admin_token}"}

        response = await self.net.delete(url, headers=headers)

        if response.status_code not in [200, 204]:
            raise KeycloakError(
                message="Session revocation failed",
                details={"error": response.text},
            )

    async def exchange_code_for_token(self, code: str, redirect_uri: str) -> KeycloakTokenResponse:
        """Exchange authorization code for tokens."""
        try:
            result = await self.client.openid.a_token(
                grant_type="authorization_code",
                code=code,
                redirect_uri=redirect_uri,
            )

            return KeycloakTokenResponse(**result)
        except KeycloakPostError as e:
            raise KeycloakError(
                "Code exchange failed",
                details={
                    "code": e.response_code,
                    "body": e.response_body,
                },
            ) from e

    async def _get_admin_token(self) -> str:
        """Get admin access token for admin API calls."""
        try:
            result = await self.client.openid.a_token(grant_type="client_credentials")
            return result["access_token"]
        except KeycloakPostError as e:
            raise KeycloakError(
                "Admin token request failed",
                details={
                    "code": e.response_code,
                    "body": e.response_body,
                },
            ) from e
