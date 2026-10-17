"""SilkShield Configuration — loads settings from environment variables."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # VirusTotal
    virustotal_api_key: str = ""

    # AI Provider
    ai_provider: str = "demo"  # "granite" | "demo"
    granite_api_url: str = ""
    granite_api_key: str = ""
    granite_model_id: str = "ibm/granite-13b-chat-v2"

    # Cache
    cache_ttl: int = 3600

    # App
    analysis_version: str = "0.1.0"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
