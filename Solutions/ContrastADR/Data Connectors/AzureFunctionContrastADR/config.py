import logging
import os


class Config:
    """Handles configuration settings."""

    @staticmethod
    def get_env_variable(key: str, default=None):
        value = os.getenv(key)
        if not value and default is None:
            logging.error(f"Environment variable {key} is not set.")
            raise ValueError(f"Missing environment variable: {key}")
        return value or default
