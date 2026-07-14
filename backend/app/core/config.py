from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://aiaudit:aiaudit@localhost:5432/aiaudit"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    JWT_SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 60
    CORS_ORIGINS: Annotated[list[str], NoDecode] = ["http://localhost:3000", "https://ai-audit.frogland.tech"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def _split_cors_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()
