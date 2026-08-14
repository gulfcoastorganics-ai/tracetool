import threading
import unittest

from backend.keylab.crypto import (
    bitcoinlib_material,
    coincurve_material,
    correctness_oracle,
    hash160,
    verify_material,
)
from backend.keylab.models import SplitKeyRequest, SyntheticSearchRequest, VanityRequest
from backend.keylab.split_key import split_key
from backend.keylab.synthetic import run_synthetic
from backend.keylab.vanity import generate_vanity, pattern_matches


class KeyLabCryptoTests(unittest.TestCase):
    def test_known_secp256k1_scalar_one(self):
        material = coincurve_material(1)
        self.assertEqual(material.public_key_hex, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        self.assertEqual(material.p2pkh_address, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")
        self.assertTrue(verify_material(material))

    def test_engine_equivalence_and_oracle(self):
        self.assertEqual(coincurve_material(1), bitcoinlib_material(1))
        matrix = correctness_oracle((1, 2, 0x12345))
        self.assertTrue(all(value == "PASS" for row in matrix.values() for value in row.values()))

    def test_hash160(self):
        material = coincurve_material(1)
        self.assertEqual(material.hash160_hex, hash160(bytes.fromhex(material.public_key_hex)).hex())
        self.assertEqual(material.p2wpkh_address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")


class KeyLabSearchTests(unittest.TestCase):
    def test_prefix_and_wildcard_matching(self):
        self.assertTrue(pattern_matches("1ABC", "1ab"))
        self.assertTrue(pattern_matches("1ABC", "1A?C", case_sensitive=True, wildcard=True))
        self.assertFalse(pattern_matches("1ABC", "1B"))

    def test_vanity_result_verifies_and_is_not_persisted(self):
        result = generate_vanity(VanityRequest(pattern="1A", max_runtime_seconds=5))
        self.assertEqual(result.status, "found")
        self.assertTrue(result.address.startswith("1A"))
        self.assertTrue(verify_material(coincurve_material(int(result.private_key, 16))))
        self.assertNotIn("private_key", result.model_dump_json().split('data/keylab'))

    def test_synthetic_range_recovery(self):
        result = run_synthetic(SyntheticSearchRequest(range_size=12, target_position=4))
        self.assertEqual(result.status, "recovered")
        self.assertTrue(result.verification)
        self.assertEqual(result.candidates_checked, 5)
        self.assertTrue(result.secret_redacted)
        self.assertLessEqual(result.target_position, result.range_size - 1)

    def test_synthetic_cancellation(self):
        cancel = threading.Event()
        cancel.set()
        result = run_synthetic(SyntheticSearchRequest(range_size=20, target_position=19), cancel)
        self.assertEqual(result.status, "cancelled")
        self.assertFalse(result.verification)

    def test_split_key_is_explicitly_disabled(self):
        result = split_key(SplitKeyRequest(pattern="1A"))
        self.assertFalse(result.enabled)
        self.assertEqual(result.status, "disabled")


if __name__ == "__main__":
    unittest.main()
