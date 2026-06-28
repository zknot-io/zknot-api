from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_parse_none_str="None",
    )

    database_url: str = "postgresql://user:password@localhost:5432/zknot"
    api_secret_key: str = "change-me-in-production"
    environment: str = "development"
    # Registry signer key for TrustSeal registration (PEM, P-256). Set as a
    # Railway secret; NEVER committed. The signer in services/registry_signer.py
    # reads the env var directly (single source of truth); declared here so the
    # settings surface stays complete. Empty default = registration disabled
    # until the secret is installed.
    zknot_registry_privkey_pem: str = ""
    # Stored as a plain comma-separated string in Railway env vars
    # e.g. CORS_ORIGINS_STR=https://zknot.io,https://verifyknot.io
    cors_origins_str: str = "https://zknot.io,https://www.zknot.io,https://verifyknot.io,http://localhost:3000,http://localhost:8000"

    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.cors_origins_str.split(",") if o.strip()]


settings = Settings()
