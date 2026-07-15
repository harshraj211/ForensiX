"""Offline authentication and role-based authorization."""

from .domain import AuthenticatedSession, Permission, Principal, RoleName
from .service import (
    AuthService,
    BootstrapAlreadyCompleteError,
    PasswordPolicyError,
)

__all__ = [
    "AuthService",
    "AuthenticatedSession",
    "BootstrapAlreadyCompleteError",
    "PasswordPolicyError",
    "Permission",
    "Principal",
    "RoleName",
]
