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


llm_config = LLMConfig()
