"""
Application configuration management.
Loads settings from environment variables and .env file.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Qwen / DashScope configuration
    dashscope_api_key: str = Field(
        default="",
        description="DashScope API key for Qwen 3.5 Plus"
    )
    qwen_model: str = Field(
        default="qwen3.5-plus",
        description="Qwen model name to use"
    )
    dashscope_base_url: str = Field(
        default="https://dashscope.aliyuncs.com/compatible-mode/v1",
        description="DashScope OpenAI-compatible base URL"
    )

    # Docker sandbox settings
    sandbox_image: str = Field(
        default="skills-check-sandbox:latest",
        description="Docker image for sandbox execution"
    )
    sandbox_timeout: int = Field(
        default=30,
        description="Sandbox execution timeout in seconds"
    )
    sandbox_memory_limit: str = Field(
        default="128m",
        description="Sandbox memory limit"
    )
    sandbox_cpu_limit: float = Field(
        default=0.5,
        description="Sandbox CPU limit (number of CPUs)"
    )

    # API settings
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


settings = Settings()
