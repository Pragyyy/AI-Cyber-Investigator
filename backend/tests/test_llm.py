import unittest

from app.llm import get_provider, get_provider_safe, parse_json_response
from app.llm.config import LLMConfig
from app.llm.providers import LLMError, MockProvider


class MockProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = get_provider(LLMConfig(provider="mock"))

    def test_returns_string_mock_response(self):
        self.assertEqual(self.provider.complete("sys", "user", mock_response="hi"), "hi")

    def test_returns_callable_mock_response(self):
        self.assertEqual(self.provider.complete("sys", "user", mock_response=lambda: "hi2"), "hi2")

    def test_no_mock_response_is_tagged_not_crashed(self):
        result = self.provider.complete("sys", "user")
        self.assertIn("[MOCK]", result)

    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            get_provider(LLMConfig(provider="not_a_real_provider"))


class SafeProviderConstructionTests(unittest.TestCase):
    """get_provider (strict) fails fast on configuration mistakes - missing key,
    missing base_url, unknown provider name - so they're caught immediately rather
    than silently masked. get_provider_safe wraps that and never raises: it's what the
    app actually calls at startup, degrading to MockProvider (with a warning) instead
    of crashing when a key hasn't been configured yet."""

    def test_strict_anthropic_without_key_raises(self):
        with self.assertRaises(ValueError):
            get_provider(LLMConfig(provider="anthropic", api_key="", model="x"))

    def test_strict_openai_compatible_without_base_url_raises(self):
        with self.assertRaises(ValueError):
            get_provider(LLMConfig(provider="openai_compatible", base_url="", model="x"))

    def test_strict_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            get_provider(LLMConfig(provider="nope"))

    def test_safe_anthropic_without_key_degrades_to_mock(self):
        provider = get_provider_safe(LLMConfig(provider="anthropic", api_key="", model="x"))
        self.assertIsInstance(provider, MockProvider)

    def test_safe_openai_compatible_without_base_url_degrades_to_mock(self):
        provider = get_provider_safe(
            LLMConfig(provider="openai_compatible", base_url="", model="x", api_key="k"))
        self.assertIsInstance(provider, MockProvider)

    def test_safe_valid_config_returns_real_provider_not_mock(self):
        provider = get_provider_safe(
            LLMConfig(provider="anthropic", api_key="sk-test", model="claude-sonnet-4-6"))
        self.assertEqual(provider.name, "anthropic")


class RemoteProviderRuntimeFallbackTests(unittest.TestCase):
    """Once a provider is successfully constructed, a runtime call failure (bad
    network, unreachable host, rate limit, timeout) must degrade to the caller's
    mock_response rather than raise - this is what keeps a single agent's LLM hiccup
    from crashing the whole investigation."""

    def test_no_mock_response_raises_llmerror_on_call_failure(self):
        provider = get_provider(LLMConfig(provider="openai_compatible",
                                          base_url="http://127.0.0.1:1", model="x",
                                          api_key="k", timeout_seconds=1))
        with self.assertRaises(LLMError):
            provider.complete("s", "u")

    def test_openai_compatible_bad_host_falls_back(self):
        cfg = LLMConfig(provider="openai_compatible", base_url="http://127.0.0.1:1",
                        model="x", api_key="k", timeout_seconds=1)
        provider = get_provider(cfg)
        self.assertEqual(provider.complete("s", "u", mock_response="fb2"), "fb2")


class JsonParsingTests(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(parse_json_response('[1,2,3]'), [1, 2, 3])

    def test_markdown_fenced_json(self):
        self.assertEqual(parse_json_response('```json\n[{"a":1}]\n```'), [{"a": 1}])

    def test_markdown_fenced_no_language_tag(self):
        self.assertEqual(parse_json_response('```\n{"a":1}\n```'), {"a": 1})

    def test_json_with_surrounding_prose(self):
        text = 'Sure, here it is: {"x": 2, "y": [1,2]} hope that helps!'
        self.assertEqual(parse_json_response(text), {"x": 2, "y": [1, 2]})

    def test_nested_brackets(self):
        text = 'prefix [1, {"nested": [1,2]}, 3] suffix'
        self.assertEqual(parse_json_response(text), [1, {"nested": [1, 2]}, 3])

    def test_stray_brace_before_real_json_is_skipped(self):
        text = 'text with a stray } then real: [{"ok": true}]'
        self.assertEqual(parse_json_response(text), [{"ok": True}])

    def test_quoted_braces_inside_strings_do_not_confuse_the_scanner(self):
        text = 'noise { before real json: {"msg": "a { b } c", "n": 1}'
        self.assertEqual(parse_json_response(text), {"msg": "a { b } c", "n": 1})

    def test_no_json_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_json_response("just plain text, no json at all")

    def test_empty_string_raises(self):
        with self.assertRaises(ValueError):
            parse_json_response("")


if __name__ == "__main__":
    unittest.main()
