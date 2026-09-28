"""Pluggable LLM providers, all speaking the same small interface.

Every provider's `complete()` accepts an optional `mock_response` - a string or a
zero-arg callable producing one - which is what MockProvider returns unconditionally,
and what every other provider falls back to if the real API call fails for any reason
(missing key, network error, rate limit, timeout). This means the multi-agent pipeline
never hard-crashes for lack of an LLM: it degrades to a clearly-labeled deterministic
explanation (see app/agents/fallback.py) instead. Real reasoning kicks in the moment a
working provider and API key are configured.
"""
from __future__ import annotations

import json
import time

import requests

from .config import llm_config

MOCK_TAG = "[MOCK]"


class LLMError(RuntimeError):
    """Raised only by providers with no mock_response to fall back to."""


class LLMProvider:
    name: str

    def complete(self, system: str, user: str, *, max_tokens: int = 1024,
                temperature: float = 0.2, mock_response=None) -> str:
        raise NotImplementedError

    def _resolve_mock(self, mock_response):
        return mock_response() if callable(mock_response) else mock_response


class MockProvider(LLMProvider):
    """No network call, no API key needed. Returns the caller-supplied deterministic
    text/JSON, tagged so it's obvious in the UI/report that this isn't real LLM
    reasoning. This is the default provider, so the whole pipeline works immediately
    without any setup."""
    name = "mock"

    def complete(self, system: str, user: str, *, max_tokens: int = 1024,
                temperature: float = 0.2, mock_response=None) -> str:
        if mock_response is None:
            return f"{MOCK_TAG} No mock_response provided for this call."
        return self._resolve_mock(mock_response)


class _RemoteProvider(LLMProvider):
    """Shared retry-to-fallback behavior for any provider that makes a real HTTP call.

    A 429 (rate limited) response is retried with exponential backoff, honoring a
    Retry-After header if the provider sends one - this matters in practice: free-tier
    providers (Groq et al.) enforce tight per-minute token limits, and a burst of
    agent calls can trip them even with spacing between requests. Any other failure
    (bad key, network error, malformed response, retries exhausted) falls through to
    the caller-supplied fallback exactly as before.
    """

    def complete(self, system: str, user: str, *, max_tokens: int = 1024,
                temperature: float = 0.2, mock_response=None) -> str:
        attempt = 0
        while True:
            try:
                return self._call(system, user, max_tokens, temperature)
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status == 429 and attempt < llm_config.max_retries:
                    wait = _retry_wait_seconds(exc.response, attempt, llm_config.retry_backoff_seconds)
                    time.sleep(wait)
                    attempt += 1
                    continue
                return self._fallback_or_raise(exc, mock_response)
            except Exception as exc:  # noqa: BLE001 - any other failure degrades to fallback
                return self._fallback_or_raise(exc, mock_response)

    def _fallback_or_raise(self, exc: Exception, mock_response) -> str:
        if mock_response is not None:
            return self._resolve_mock(mock_response)
        raise LLMError(f"{self.name} call failed and no fallback was provided: {exc}") from exc

    def _call(self, system: str, user: str, max_tokens: int, temperature: float) -> str:
        raise NotImplementedError


def _retry_wait_seconds(response, attempt: int, backoff_base: float) -> float:
    """Prefer the server's own Retry-After header (Groq and most OpenAI-compatible
    APIs send one on 429s); fall back to exponential backoff if it's absent."""
    retry_after = response.headers.get("Retry-After") if response is not None else None
    if retry_after:
        try:
            return max(float(retry_after), 0.0)
        except ValueError:
            pass
    return backoff_base * (2 ** attempt)


class AnthropicProvider(_RemoteProvider):
    """Calls the Anthropic Messages API directly over HTTP (no SDK dependency, so the
    base install stays light)."""
    name = "anthropic"
    API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str, model: str, timeout: int = 60):
        if not api_key:
            raise ValueError("AnthropicProvider requires an API key (LLM_API_KEY).")
        self.api_key = api_key
        self.model = model or "claude-sonnet-4-6"
        self.timeout = timeout

    def _call(self, system: str, user: str, max_tokens: int, temperature: float) -> str:
        resp = requests.post(
            self.API_URL,
            headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01",
                    "content-type": "application/json"},
            json={"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                 "system": system, "messages": [{"role": "user", "content": user}]},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return "".join(block.get("text", "") for block in data.get("content", [])
                       if block.get("type") == "text").strip()


class OpenAICompatibleProvider(_RemoteProvider):
    """Works with any provider exposing an OpenAI-style /chat/completions endpoint:
    OpenAI itself, Groq, Together, OpenRouter, a local Ollama/vLLM server, etc. Set
    LLM_BASE_URL accordingly (e.g. https://api.groq.com/openai/v1)."""
    name = "openai_compatible"

    def __init__(self, api_key: str, model: str, base_url: str, timeout: int = 60):
        if not base_url:
            raise ValueError("OpenAICompatibleProvider requires LLM_BASE_URL.")
        if not model:
            raise ValueError("OpenAICompatibleProvider requires LLM_MODEL.")
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _call(self, system: str, user: str, max_tokens: int, temperature: float) -> str:
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        resp = requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json={"model": self.model, "max_tokens": max_tokens, "temperature": temperature,
                 "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()


def get_provider(cfg) -> LLMProvider:
    """Strict: raises on missing/invalid configuration (wrong provider name, missing
    API key, missing base_url). Use this when you want configuration mistakes caught
    immediately rather than silently masked."""
    if cfg.provider == "mock":
        return MockProvider()
    if cfg.provider == "anthropic":
        return AnthropicProvider(cfg.api_key, cfg.model, cfg.timeout_seconds)
    if cfg.provider == "openai_compatible":
        return OpenAICompatibleProvider(cfg.api_key, cfg.model, cfg.base_url, cfg.timeout_seconds)
    raise ValueError(f"Unknown LLM provider '{cfg.provider}'. "
                     f"Choose from ['mock', 'anthropic', 'openai_compatible'].")


def get_provider_safe(cfg) -> LLMProvider:
    """Never raises: falls back to MockProvider (with a printed warning) if the
    configured provider can't even be constructed - e.g. an API key hasn't been added
    yet. This is what the app actually uses at startup/graph-build time, so a missing
    key degrades the affected agents to their deterministic fallback text instead of
    crashing the whole investigation pipeline. Runtime call failures (bad network, rate
    limits) are handled separately, inside complete() itself - see _RemoteProvider."""
    try:
        return get_provider(cfg)
    except Exception as exc:  # noqa: BLE001 - any construction failure degrades to mock
        print(f"[llm] Falling back to the mock provider: {exc}")
        return MockProvider()


def _find_balanced_json(text: str):
    """Scan left to right; at each '{' or '[' try to find its matching close (respecting
    nesting and quoted strings) and parse that span. Returns the first span that parses
    as valid JSON, or None."""
    openers, closers = "{[", "}]"
    for i, ch in enumerate(text):
        if ch not in openers:
            continue
        stack = [ch]
        in_string, escape = False, False
        for j in range(i + 1, len(text)):
            c = text[j]
            if in_string:
                if escape:
                    escape = False
                elif c == "\\":
                    escape = True
                elif c == '"':
                    in_string = False
                continue
            if c == '"':
                in_string = True
            elif c in openers:
                stack.append(c)
            elif c in closers:
                if not stack:
                    break
                expected = "}" if stack[-1] == "{" else "]"
                if c != expected:
                    break
                stack.pop()
                if not stack:
                    candidate = text[i:j + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        break
    return None


def parse_json_response(text: str) -> dict | list:
    """LLMs sometimes wrap JSON in markdown fences or add a sentence before/after it.
    Strip fences, then find the first balanced {...} or [...] span that parses."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("```")[1]
        if stripped.lstrip().startswith(("json", "JSON")):
            stripped = stripped.split("\n", 1)[1] if "\n" in stripped else ""
    stripped = stripped.strip()

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass

    result = _find_balanced_json(stripped)
    if result is not None:
        return result
    raise ValueError(f"Could not parse JSON from LLM response: {text[:200]!r}")
