import base64
import os
import unittest


class ConfigCollectorHelpersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Import after dependencies are installed (requirements.txt is used in CI).
        import main
        cls.main = main

    def test_source_urls_env_overrides_defaults(self):
        old = os.environ.get("SOURCE_SUBSCRIPTION_URLS")
        try:
            os.environ["SOURCE_SUBSCRIPTION_URLS"] = "https://one.example/a,\nhttps://two.example/b"
            self.assertEqual(self.main.configured_source_urls(), [
                "https://one.example/a", "https://two.example/b"
            ])
        finally:
            if old is None:
                os.environ.pop("SOURCE_SUBSCRIPTION_URLS", None)
            else:
                os.environ["SOURCE_SUBSCRIPTION_URLS"] = old

    def test_extract_plain_and_base64_source(self):
        link = "vless://abc@example.com:443?security=tls&type=tcp#one"
        self.assertIn(link, self.main.extract_configs_from_source_text(link))
        encoded = base64.b64encode((link + "\n").encode()).decode()
        self.assertIn(link, self.main.extract_configs_from_source_text(encoded))

    def test_candidate_cap_and_deduplication(self):
        first = {f"vless://{i}@one.example:443" for i in range(700)}
        second = {f"vless://{i}@two.example:443" for i in range(700)}
        selected = self.main.select_candidate_configs([first, second, {next(iter(first))}], 1000)
        self.assertEqual(len(selected), 1000)
        self.assertEqual(len(set(selected)), 1000)


if __name__ == "__main__":
    unittest.main()
