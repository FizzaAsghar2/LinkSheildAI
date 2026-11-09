from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    database_url:str="sqlite:///./linkshield.db"
    cerebras_api_key:str=""
    cerebras_model:str="llama3.1-8b"
    web_risk_api_key:str=""
    web_risk_enabled:bool=False
    official_domains:str=""
    allowed_origins:str="http://localhost:5173,http://127.0.0.1:5173"
    max_response_bytes:int=1500000
    request_timeout_seconds:float=8
    model_config=SettingsConfigDict(env_file=".env",extra="ignore")
settings=Settings()
