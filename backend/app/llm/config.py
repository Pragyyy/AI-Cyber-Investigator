"""LLM configuration. Provider is modular and swappable via environment variables -
the rest of the app only ever talks to the LLMProvider interface (see base.py)."""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class LLMConfig:
    # "mock" needs no API key and no network call - a deterministic, clearly-labeled
    # stand-in used by default so the whole pipeline works out of the box. Switch to
    # "anthropic" or "openai_compatible" (Groq, Together, OpenRouter, local
    # Ollama-compatible servers, ...) once you add an API key.
    provider: str = os.getenv("LLM_PROVIDER", "mock")
    model: str = os.getenv("LLM_MODEL", "")
    api_key: str = os.getenv("LLM_API_KEY", "")
    base_url: str = os.getenv("LLM_BASE_URL", "")  # only used by openai_compatible
    max_tokens: int = int(os.getenv("LLM_MAX_TOKENS", "1024"))
    temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.2"))
    timeout_seconds: int = int(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
    # Free-tier providers (Groq et al.) enforce tight per-minute rate limits. A small
    # delay between agent calls avoids tripping them proactively; max_retries handles
    # it reactively if a burst still gets rate-limited (see providers.py). Both only
    # apply to real remote providers - the mock provider skips both entirely, so the
    # test suite and local development stay fast.
    request_delay_seconds: float = float(os.getenv("LLM_REQUEST_DELAY_SECONDS", "0"))
    max_retries: int = int(os.getenv("LLM_MAX_RETRIES", "2"))
    retry_backoff_seconds: float = float(os.getenv("LLM_RETRY_BACKOFF_SECONDS", "2"))


llm_config = LLMConfig()
