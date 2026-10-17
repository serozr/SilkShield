"""SilkShield Configuration — loads settings from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # VirusTotal
    virustotal_api_key: str = ""

    # AI provider selector
    ai_provider: str = "demo"  # "local" | "granite" | "demo"

    # Local llama.cpp OpenAI-compatible endpoint (no key required)\n    local_llm_api_url: str = "http://127.0.0.1:8080/v1/chat/completions"\n    local_llm_model_id: str = "local-granite"\n\n    # IBM watsonx.ai Runtime settings for Granite
    granite_api_url: str = ""  # regional base URL, e.g. https://us-south.ml.cloud.ibm.com
    granite_api_key: str = ""  # IBM Cloud API key; exchanged for IAM bearer token
    watsonx_project_id: str = ""
    granite_model_id: str = "ibm/granite-4-h-small"

    # Cache
    cache_ttl: int = 3600

    # App
    analysis_version: str = "0.1.0"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
