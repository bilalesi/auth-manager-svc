"""FastAPI dependency injection functions.

This module provides dependency injection functions for FastAPI routes.
These dependencies handle the creation and lifecycle of service instances,
database sessions, and other shared resources.

"""

from typing import Annotated, AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.base import db_manager
from app.db.repositories.token_vault import VaultRepository
from app.services.encryption import EncryptionService
from app.services.keycloak import KeycloakService
from app.services.state_token import AcknowledgementKeycloakStateService
from app.services.token_vault import VaultService


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield a database session, to be used as a dependency."""
    async for session in db_manager.session():
        yield session


def get_encryption_service() -> EncryptionService:
    """Dependency for getting the encryption service."""
    settings = get_settings()
    return EncryptionService(settings.encryption.token_vault_encryption_key)


def get_keycloak_service() -> KeycloakService:
    """Dependency for getting the Keycloak service."""
    settings = get_settings()
    return KeycloakService(settings.keycloak)


def get_state_token_service() -> AcknowledgementKeycloakStateService:
    """Dependency for getting the state token service."""
    settings = get_settings()
    return AcknowledgementKeycloakStateService(secret_key=settings.state_token.secret)


SessionDep = Annotated[AsyncSession, Depends(get_db)]
EncryptionDep = Annotated[EncryptionService, Depends(get_encryption_service)]
KeycloakDep = Annotated[KeycloakService, Depends(get_keycloak_service)]
StateTokenDep = Annotated[AcknowledgementKeycloakStateService, Depends(get_state_token_service)]


def get_token_vault_repository(session: SessionDep) -> VaultRepository:
    """Dependency for getting the token vault repository."""
    return VaultRepository(session)


def get_token_vault_service(
    repository: Annotated[VaultRepository, Depends(get_token_vault_repository)],
    encryption: EncryptionDep,
) -> VaultService:
    """Dependency for getting the token vault service."""
    return VaultService(repository, encryption)


TokenVaultRepoDep = Annotated[VaultRepository, Depends(get_token_vault_repository)]
TokenVaultServiceDep = Annotated[VaultService, Depends(get_token_vault_service)]
