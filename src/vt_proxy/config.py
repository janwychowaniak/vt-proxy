from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, 12-Factor style (SPEC §10).

    Values come from the environment (or a local .env for development) and are
    validated at startup; a missing VT_API_KEY refuses to boot. Outbound proxy
    settings (HTTP_PROXY/HTTPS_PROXY/NO_PROXY) are intentionally NOT modeled
    here — httpx honors them from the environment directly.

    CA_FILE is only a path here. The file is checked in the app factory, so a
    refusal can print one line of its own (SPEC §10); unset or empty means absent.
    """

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    vt_api_key: str
    vt_base_url: str = "https://www.virustotal.com/api/v3"
    vt_timeout: float = 30.0
    log_level: str = "INFO"
    ca_file: str | None = None
