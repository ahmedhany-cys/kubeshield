"""Runtime configuration loaded from environment variables (prefix KUBESHIELD_)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="KUBESHIELD_", env_file=".env", extra="ignore")

    environment: Literal["development", "production", "test"] = "production"
    database_url: str = "postgresql+psycopg://kubeshield@localhost:5432/kubeshield"

    # Secrets. No defaults: the application refuses to start without them.
    jwt_secret: SecretStr = Field(..., min_length=32)
    ingest_token: SecretStr = Field(..., min_length=32)
    admin_username: str = "admin"
    # Used once to create the bootstrap admin account when no users exist.
    admin_password: SecretStr | None = None

    session_ttl_minutes: int = Field(480, ge=5, le=1440)
    cookie_secure: bool = True

    # Kubernetes access: "in-cluster", "kubeconfig" or "disabled".
    kube_mode: Literal["in-cluster", "kubeconfig", "disabled"] = "in-cluster"
    kube_context: str | None = None

    # Namespaces carrying this label (value "true") are the isolated laboratory.
    # Response actions and attack simulations are refused anywhere else.
    lab_label: str = "kubeshield.io/lab"
    # Namespace used for server-side dry-run admission checks of manifests.
    preflight_namespace: str = "kubeshield-preflight"

    hubble_relay_address: str | None = "hubble-relay.kube-system.svc:80"
    trivy_binary: str = "trivy"
    trivy_timeout_seconds: int = 600
    trivy_cache_dir: str | None = None

    inventory_interval_seconds: int = Field(60, ge=10)
    policy_interval_seconds: int = Field(60, ge=10)
    flow_retention: int = Field(20000, ge=1000)
    incident_window_minutes: int = Field(30, ge=1)

    static_dir: str | None = None
    workers_enabled: bool = True

    @field_validator("database_url")
    @classmethod
    def _no_inline_default_password(cls, v: str) -> str:
        if "change-me" in v:
            raise ValueError("refusing to start with a placeholder database password")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
