from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_SECRETS = {"", "change-me-in-production", "secret", "changeme"}


class Settings(BaseSettings):
    """Application settings, read from environment variables / .env."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    APP_NAME: str = "Secure File Scanner API"
    APP_ENV: str = "development"  # development | test | production

    DATABASE_URL: str = "postgresql+asyncpg://scanner:scanner@db:5432/scanner"
    REDIS_URL: str = "redis://redis:6379/0"

    JWT_SECRET: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30, ge=1)
    BCRYPT_ROUNDS: int = Field(default=12, ge=4, le=16)

    MAX_FILE_SIZE_MB: int = Field(default=10, ge=1)
    STORAGE_PATH: str = "./storage"

    RATE_LIMIT_LOGIN: int = Field(default=5, ge=1)  # attempts per minute per IP
    RATE_LIMIT_UPLOAD: int = Field(default=20, ge=1)  # requests per minute per user

    MAX_ARCHIVE_FILES: int = Field(default=500, ge=1)
    MAX_EXTRACTED_SIZE_MB: int = Field(default=100, ge=1)
    MAX_ARCHIVE_DEPTH: int = Field(default=2, ge=0)

    SCAN_TIME_LIMIT_SECONDS: int = Field(default=300, ge=10)
    CELERY_TASK_ALWAYS_EAGER: bool = False  # run tasks inline (development only)

    LOG_LEVEL: str = "INFO"

    @field_validator("JWT_ALGORITHM")
    @classmethod
    def _only_hmac_algorithms(cls, v: str) -> str:
        # Never allow "none" or asymmetric algorithms with a shared secret.
        if v not in {"HS256", "HS384", "HS512"}:
            raise ValueError("JWT_ALGORITHM must be one of HS256, HS384, HS512")
        return v

    @field_validator("LOG_LEVEL")
    @classmethod
    def _normalize_level(cls, v: str) -> str:
        v = v.upper()
        if v not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("invalid LOG_LEVEL")
        return v

    @property
    def max_file_size_bytes(self) -> int:
        return self.MAX_FILE_SIZE_MB * 1024 * 1024

    @property
    def max_extracted_size_bytes(self) -> int:
        return self.MAX_EXTRACTED_SIZE_MB * 1024 * 1024

    def validate_for_runtime(self) -> None:
        """Refuse to start in production with an insecure JWT secret."""
        if self.APP_ENV == "production":
            if self.JWT_SECRET in INSECURE_SECRETS or len(self.JWT_SECRET) < 32:
                raise RuntimeError(
                    "JWT_SECRET must be a random value of at least 32 characters in production"
                )


@lru_cache
def get_settings() -> Settings:
    return Settings()
