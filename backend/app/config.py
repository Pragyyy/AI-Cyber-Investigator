"""Central configuration, read from environment variables (and .env if present)."""
import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # project root (contains backend/, data/, ...)

try:  # python-dotenv is optional at import time; it is listed in requirements.txt
    from dotenv import load_dotenv

    load_dotenv(ROOT / ".env")
except ImportError:  # pragma: no cover
    pass


def _resolve_path(value: str) -> str:
    p = Path(value)
    return str(p if p.is_absolute() else ROOT / p)


@dataclass(frozen=True)
class Settings:
    db_path: str = _resolve_path(os.getenv("DB_PATH", "data/investigator.db"))
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "20"))
    cors_origins: tuple = tuple(
        o.strip()
        for o in os.getenv(
            "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
        ).split(",")
        if o.strip()
    )
    sample_dir: str = str(ROOT / "data" / "sample_logs")

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


settings = Settings()
