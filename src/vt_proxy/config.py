from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, 12-Factor style (SPEC §10).

    Values come from the environment (or a local .env for development) and are
    validated at startup; a missing VT_API_KEY refuses to boot. Outbound proxy
    settings (HTTP_PROXY/HTTPS_PROXY/NO_PROXY) are intentionally NOT modeled
    here — httpx honors them from the environment directly.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    vt_api_key: str
    vt_base_url: str = "https://www.virustotal.com/api/v3"
    vt_timeout: float = 30.0
    log_level: str = "INFO"
