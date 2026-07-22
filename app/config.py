from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Homelab Sentinel"
    app_env: str = "production"
    secret_key: str = "change-me"
    ingest_token: str = "change-me-too"
    database_url: str = "sqlite:////data/sentinel.db"
    opnsense_source_name: str = "firewall"
    vps_source_name: str = "remote-server"
    recent_event_limit: int = 50

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
