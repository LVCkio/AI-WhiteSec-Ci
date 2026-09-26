from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI WhiteSec CI"
    database_url: str = "sqlite:///./ai_whitesec.db"
    inference_url: str = "http://localhost:8001"
    ai_confidence_threshold: float = 0.70
    cors_origins: str = "http://localhost:8000,http://localhost:3000"
    # API key for protecting /api/* endpoints.
    # Set API_KEY in .env to enable authentication; leave empty to disable (dev only).
    api_key: str = ""
    # Log level: DEBUG | INFO | WARNING | ERROR
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @property
    def auth_enabled(self) -> bool:
        return bool(self.api_key.strip())


@lru_cache
def get_settings() -> Settings:
    return Settings()

