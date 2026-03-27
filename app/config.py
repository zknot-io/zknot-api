from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    database_url: str = "postgresql://user:password@localhost:5432/zknot"
    api_secret_key: str = "change-me-in-production"
    environment: str = "development"
    cors_origins: List[str] = [
        "https://zknot.io",
        "https://www.zknot.io",
        "https://verifyknot.io",
        "http://localhost:3000",
        "http://localhost:8000",
    ]


settings = Settings()
