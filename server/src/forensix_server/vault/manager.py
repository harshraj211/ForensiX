"""Secure evidence vault using Fernet symmetric encryption."""

# mypy: ignore-errors

# ruff: noqa: B904

import base64
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi import HTTPException, status


class VaultManager:
    """Manages secure storage of sensitive forensic artifacts."""

    def __init__(self, storage_path: Path, encryption_key: str | None = None):
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # If no key provided, Vault is disabled or will raise errors on use
        self.fernet = None
        if encryption_key:
            try:
                # Support plain 32-byte string or base64 encoded Fernet key
                if len(encryption_key) == 32:
                    key = base64.urlsafe_b64encode(encryption_key.encode("utf-8"))
                else:
                    key = encryption_key.encode("utf-8")
                self.fernet = Fernet(key)
            except Exception as e:
                raise ValueError(f"Invalid vault encryption key: {e}")

    def _ensure_active(self):
        if not self.fernet:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Vault is not configured. Add FORENSIX_VAULT_ENCRYPTION_KEY to .env.",
            )

    def store_file(self, case_id: str, file_path: Path) -> str:
        """Encrypt and store a file, returning its vault locator."""
        self._ensure_active()

        with open(file_path, "rb") as f:
            data = f.read()

        encrypted_data = self.fernet.encrypt(data)  # type: ignore

        vault_filename = f"{case_id}_{file_path.name}.enc"
        vault_path = self.storage_path / vault_filename

        with open(vault_path, "wb") as f:
            f.write(encrypted_data)

        return vault_filename

    def retrieve_file(self, vault_filename: str) -> bytes:
        """Retrieve and decrypt a file from the vault."""
        self._ensure_active()

        vault_path = self.storage_path / vault_filename
        if not vault_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="File not found in vault."
            )

        with open(vault_path, "rb") as f:
            encrypted_data = f.read()

        try:
            decrypted_data = self.fernet.decrypt(encrypted_data)  # type: ignore
            return decrypted_data
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to decrypt vault file: {e}",
            )
