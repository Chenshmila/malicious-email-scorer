from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    api_key: str
    anthropic_api_key: str
    model: str = "claude-haiku-4-5-20251001"
    log_level: str = "INFO"

    class Config:
        env_file = ".env"


settings = Settings()
