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
    # Stored as a plain comma-separated string in Railway env vars
    # e.g. CORS_ORIGINS_STR=https://zknot.io,https://verifyknot.io
    cors_origins_str: str = "https://zknot.io,https://www.zknot.io,https://verifyknot.io,http://localhost:3000,http://localhost:8000"

    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.cors_origins_str.split(",") if o.strip()]


settings = Settings()
