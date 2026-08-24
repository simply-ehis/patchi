"""Unit tests for patchi.core.hosted.tokens"""

import tempfile
import unittest
from pathlib import Path

from patchi.core.hosted.tokens import count, generate, list_tokens, revoke, validate


class TestTokens(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_generate_and_validate(self):
        plaintext = generate(self.root, "test-token")
        self.assertIsInstance(plaintext, str)
        self.assertEqual(len(plaintext), 64)  # 32 bytes hex

        result = validate(self.root, plaintext)
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "test-token")
        self.assertIn("id", result)
        self.assertIn("created_at", result)

    def test_validate_wrong_token(self):
        generate(self.root, "test")
        result = validate(self.root, "wrong-token-string" * 4)
        self.assertIsNone(result)

    def test_list_tokens(self):
        generate(self.root, "tok1")
        generate(self.root, "tok2")
        tokens = list_tokens(self.root)
        self.assertEqual(len(tokens), 2)
        names = [t["name"] for t in tokens]
        self.assertIn("tok1", names)
        self.assertIn("tok2", names)
        # Hash should not be in the output
        for t in tokens:
            self.assertNotIn("hash", t)

    def test_revoke(self):
        generate(self.root, "to-revoke")
        tokens = list_tokens(self.root)
        token_id = tokens[0]["id"]
        ok = revoke(self.root, token_id)
        self.assertTrue(ok)
        self.assertEqual(len(list_tokens(self.root)), 0)

    def test_revoke_nonexistent(self):
        ok = revoke(self.root, "nonexistent-id")
        self.assertFalse(ok)

    def test_count(self):
        self.assertEqual(count(self.root), 0)
        generate(self.root, "a")
        generate(self.root, "b")
        self.assertEqual(count(self.root), 2)

    def test_per_installation_key(self):
        """Each root gets a unique HMAC key."""
        from patchi.core.hosted.tokens import _get_hmac_key

        key1 = _get_hmac_key(self.root)
        key2 = _get_hmac_key(self.root)
        self.assertEqual(key1, key2)  # same root = same key

        tmpdir2 = tempfile.TemporaryDirectory()
        root2 = Path(tmpdir2.name)
        key3 = _get_hmac_key(root2)
        self.assertNotEqual(key1, key3)  # different root = different key
        tmpdir2.cleanup()

    def test_last_used_updated(self):
        plaintext = generate(self.root, "test")
        # First validate sets last_used
        result = validate(self.root, plaintext)
        self.assertIsNotNone(result.get("last_used"))
        first_used = result["last_used"]

        # Second validate updates it
        import time

        time.sleep(0.01)
        result2 = validate(self.root, plaintext)
        self.assertGreaterEqual(result2["last_used"], first_used)

    def test_empty_root(self):
        tokens = list_tokens(Path("/nonexistent/path"))
        self.assertEqual(tokens, [])


if __name__ == "__main__":
    unittest.main()
