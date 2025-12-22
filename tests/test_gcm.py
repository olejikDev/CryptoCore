#!/usr/bin/env python3
"""
РўРµСЃС‚С‹ РґР»СЏ GCM (Galois/Counter Mode) - Sprint 6
"""

import os
import unittest
import tempfile
from src.modes.gcm import GCM, AuthenticationError


class TestGCM(unittest.TestCase):
    """РўРµСЃС‚С‹ РґР»СЏ СЂРµР°Р»РёР·Р°С†РёРё GCM"""

    def setUp(self):
        """РќР°СЃС‚СЂРѕР№РєР° С‚РµСЃС‚РѕРІ"""
        self.key_128 = os.urandom(16)  # AES-128 РєР»СЋС‡
        self.key_256 = os.urandom(32)  # AES-256 РєР»СЋС‡
        self.test_data = b"Hello, GCM World! This is test data for authenticated encryption."
        self.test_aad = b"Additional authenticated data for testing"

    def test_gcm_basic_encryption_decryption(self):
        """РўРµСЃС‚ Р±Р°Р·РѕРІРѕРіРѕ С€РёС„СЂРѕРІР°РЅРёСЏ Рё СЂР°СЃС€РёС„СЂРѕРІР°РЅРёСЏ"""
        print("\n=== Test 1: Basic GCM encryption/decryption ===")

        # РЎРѕР·РґР°РµРј GCM РѕР±СЉРµРєС‚
        gcm = GCM(self.key_128)

        # РЁРёС„СЂСѓРµРј
        ciphertext = gcm.encrypt(self.test_data, self.test_aad)

        # РџСЂРѕРІРµСЂСЏРµРј СЃС‚СЂСѓРєС‚СѓСЂСѓ (nonce + ciphertext + tag)
        self.assertEqual(len(ciphertext),
                         12 + len(self.test_data) + 16)  # nonce(12) + data + tag(16)

        # Р Р°СЃС€РёС„СЂРѕРІС‹РІР°РµРј - РџР•Р Р•Р”РђР•Рњ Р’Р•РЎР¬ CIPHERTEXT
        gcm2 = GCM(self.key_128, gcm.nonce)
        plaintext = gcm2.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, self.test_data)
        print("вњ“ Basic GCM test passed")

    def test_gcm_with_different_key_sizes(self):
        """РўРµСЃС‚ СЃ СЂР°Р·РЅС‹РјРё СЂР°Р·РјРµСЂР°РјРё РєР»СЋС‡РµР№"""
        print("\n=== Test 2: Different key sizes ===")

        for key in [self.key_128, self.key_256]:
            gcm = GCM(key)
            ciphertext = gcm.encrypt(self.test_data, self.test_aad)

            gcm2 = GCM(key, gcm.nonce)
            plaintext = gcm2.decrypt(ciphertext, self.test_aad)

            self.assertEqual(plaintext, self.test_data)

        print("вњ“ Different key sizes test passed")

    def test_gcm_authentication_failure_wrong_aad(self):
        """РўРµСЃС‚ РЅРµСѓРґР°С‡Рё Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё РїСЂРё РЅРµРІРµСЂРЅРѕРј AAD"""
        print("\n=== Test 3: Authentication failure with wrong AAD ===")

        gcm = GCM(self.key_128)
        ciphertext = gcm.encrypt(self.test_data, self.test_aad)

        # РЎРѕР·РґР°РµРј GCM СЃ РїСЂР°РІРёР»СЊРЅС‹Рј nonce
        gcm2 = GCM(self.key_128, gcm.nonce)

        # РџСЂРѕР±СѓРµРј СЂР°СЃС€РёС„СЂРѕРІР°С‚СЊ СЃ РЅРµРІРµСЂРЅС‹Рј AAD
        with self.assertRaises(AuthenticationError):
            gcm2.decrypt(ciphertext, b"wrong aad")

        print("вњ“ Wrong AAD detection test passed")

    def test_gcm_authentication_failure_tampered_ciphertext(self):
        """РўРµСЃС‚ РЅРµСѓРґР°С‡Рё Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё РїСЂРё РёР·РјРµРЅРµРЅРЅРѕРј С€РёС„СЂС‚РµРєСЃС‚Рµ"""
        print("\n=== Test 4: Authentication failure with tampered ciphertext ===")

        gcm = GCM(self.key_128)
        ciphertext = gcm.encrypt(self.test_data, self.test_aad)

        # РР·РјРµРЅСЏРµРј РѕРґРёРЅ Р±Р°Р№С‚ РІ ciphertext (РЅРµ РІ nonce!)
        tampered = bytearray(ciphertext)
        tampered[20] ^= 0x01  # РР·РјРµРЅСЏРµРј Р±Р°Р№С‚ РІ ciphertext С‡Р°СЃС‚Рё (РЅРµ РїРµСЂРІС‹Рµ 12 Р±Р°Р№С‚ nonce)

        gcm2 = GCM(self.key_128, gcm.nonce)

        with self.assertRaises(AuthenticationError):
            gcm2.decrypt(bytes(tampered), self.test_aad)

        print("вњ“ Tampered ciphertext detection test passed")

    def test_gcm_empty_aad(self):
        """РўРµСЃС‚ СЃ РїСѓСЃС‚С‹Рј AAD"""
        print("\n=== Test 5: Empty AAD ===")

        gcm = GCM(self.key_128)
        ciphertext = gcm.encrypt(self.test_data, b"")

        gcm2 = GCM(self.key_128, gcm.nonce)
        plaintext = gcm2.decrypt(ciphertext, b"")

        self.assertEqual(plaintext, self.test_data)
        print("вњ“ Empty AAD test passed")

    def test_gcm_empty_plaintext(self):
        """РўРµСЃС‚ СЃ РїСѓСЃС‚С‹Рј plaintext"""
        print("\n=== Test 6: Empty plaintext ===")

        gcm = GCM(self.key_128)
        ciphertext = gcm.encrypt(b"", self.test_aad)

        # РџСЂРѕРІРµСЂСЏРµРј СЂР°Р·РјРµСЂ (nonce + tag)
        self.assertEqual(len(ciphertext), 12 + 16)  # nonce + tag

        gcm2 = GCM(self.key_128, gcm.nonce)
        plaintext = gcm2.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, b"")
        print("вњ“ Empty plaintext test passed")

    def test_gcm_large_data(self):
        """РўРµСЃС‚ СЃ Р±РѕР»СЊС€РёРјРё РґР°РЅРЅС‹РјРё"""
        print("\n=== Test 7: Large data ===")

        large_data = os.urandom(1024 * 1024)  # 1 MB РґР°РЅРЅС‹С…
        gcm = GCM(self.key_128)

        ciphertext = gcm.encrypt(large_data, self.test_aad)
        gcm2 = GCM(self.key_128, gcm.nonce)
        plaintext = gcm2.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, large_data)
        print("вњ“ Large data test passed")

    def test_gcm_nonce_uniqueness(self):
        """РўРµСЃС‚ СѓРЅРёРєР°Р»СЊРЅРѕСЃС‚Рё nonce"""
        print("\n=== Test 8: Nonce uniqueness ===")

        nonces = set()
        for _ in range(100):
            gcm = GCM(self.key_128)
            nonces.add(gcm.nonce.hex())

        # Р’СЃРµ nonce РґРѕР»Р¶РЅС‹ Р±С‹С‚СЊ СѓРЅРёРєР°Р»СЊРЅС‹РјРё
        self.assertEqual(len(nonces), 100)
        print("вњ“ Nonce uniqueness test passed")

    def test_gcm_file_encryption_decryption(self):
        """РўРµСЃС‚ С€РёС„СЂРѕРІР°РЅРёСЏ Рё СЂР°СЃС€РёС„СЂРѕРІР°РЅРёСЏ С„Р°Р№Р»РѕРІ"""
        print("\n=== Test 9: File encryption/decryption ===")

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # РЎРѕР·РґР°РµРј С‚РµСЃС‚РѕРІС‹Р№ С„Р°Р№Р»
            f.write(self.test_data)
            input_file = f.name

        try:
            # РЁРёС„СЂСѓРµРј С„Р°Р№Р»
            gcm = GCM(self.key_128)
            ciphertext = gcm.encrypt(self.test_data, self.test_aad)

            # РЎРѕС…СЂР°РЅСЏРµРј Р·Р°С€РёС„СЂРѕРІР°РЅРЅС‹Рµ РґР°РЅРЅС‹Рµ
            encrypted_file = input_file + '.enc'
            with open(encrypted_file, 'wb') as f:
                f.write(ciphertext)

            # Р Р°СЃС€РёС„СЂРѕРІС‹РІР°РµРј
            with open(encrypted_file, 'rb') as f:
                ciphertext_from_file = f.read()

            gcm2 = GCM(self.key_128, gcm.nonce)
            plaintext = gcm2.decrypt(ciphertext_from_file, self.test_aad)

            self.assertEqual(plaintext, self.test_data)
            print("вњ“ File encryption/decryption test passed")

        finally:
            # РћС‡РёСЃС‚РєР°
            if os.path.exists(input_file):
                os.remove(input_file)
            if os.path.exists(input_file + '.enc'):
                os.remove(input_file + '.enc')

    def test_gcm_with_provided_nonce(self):
        """РўРµСЃС‚ СЃ РїСЂРµРґРѕСЃС‚Р°РІР»РµРЅРЅС‹Рј nonce"""
        print("\n=== Test 10: GCM with provided nonce ===")

        # РЎРѕР·РґР°РµРј С„РёРєСЃРёСЂРѕРІР°РЅРЅС‹Р№ nonce
        nonce = b"\x00" * 12  # 12 РЅСѓР»РµРІС‹С… Р±Р°Р№С‚

        gcm = GCM(self.key_128, nonce)
        ciphertext = gcm.encrypt(self.test_data, self.test_aad)

        # РџСЂРѕРІРµСЂСЏРµРј С‡С‚Рѕ nonce РІ РЅР°С‡Р°Р»Рµ ciphertext СЃРѕРІРїР°РґР°РµС‚
        self.assertEqual(ciphertext[:12], nonce)

        gcm2 = GCM(self.key_128, nonce)
        plaintext = gcm2.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, self.test_data)
        print("вњ“ GCM with provided nonce test passed")

    def test_gcm_iv_attribute(self):
        """РўРµСЃС‚ С‡С‚Рѕ Р°С‚СЂРёР±СѓС‚ iv РґРѕСЃС‚СѓРїРµРЅ (РґР»СЏ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё)"""
        print("\n=== Test 11: IV attribute test ===")

        gcm = GCM(self.key_128)

        # РџСЂРѕРІРµСЂСЏРµРј С‡С‚Рѕ РµСЃС‚СЊ Р°С‚СЂРёР±СѓС‚ nonce
        self.assertTrue(hasattr(gcm, 'nonce'))
        self.assertEqual(len(gcm.nonce), 12)

        # Р”Р»СЏ РѕР±СЂР°С‚РЅРѕР№ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё РјРѕР¶РµС‚ Р±С‹С‚СЊ Р°С‚СЂРёР±СѓС‚ iv
        if hasattr(gcm, 'iv'):
            self.assertEqual(gcm.iv, gcm.nonce)

        print("вњ“ IV attribute test passed")

    def test_gcm_chunk_processing(self):
        """РўРµСЃС‚ РѕР±СЂР°Р±РѕС‚РєРё РґР°РЅРЅС‹С… РїРѕ С‡Р°СЃС‚СЏРј (РµСЃР»Рё СЂРµР°Р»РёР·РѕРІР°РЅРѕ)"""
        print("\n=== Test 12: Chunk processing test ===")

        # РЎРѕР·РґР°РµРј РґР°РЅРЅС‹Рµ, РєРѕС‚РѕСЂС‹Рµ Р±СѓРґСѓС‚ РѕР±СЂР°Р±Р°С‚С‹РІР°С‚СЊСЃСЏ РїРѕ С‡Р°СЃС‚СЏРј
        data_parts = [
            b"Part 1: ",
            b"Part 2: ",
            b"Part 3: Final data"
        ]

        full_data = b"".join(data_parts)

        gcm = GCM(self.key_128)
        ciphertext = gcm.encrypt(full_data, self.test_aad)

        gcm2 = GCM(self.key_128, gcm.nonce)
        plaintext = gcm2.decrypt(ciphertext, self.test_aad)

        self.assertEqual(plaintext, full_data)
        print("вњ“ Chunk processing test passed")

    def test_gcm_error_handling(self):
        """РўРµСЃС‚ РѕР±СЂР°Р±РѕС‚РєРё РѕС€РёР±РѕРє"""
        print("\n=== Test 13: Error handling test ===")

        gcm = GCM(self.key_128)

        # РЎР»РёС€РєРѕРј РєРѕСЂРѕС‚РєРёРµ РґР°РЅРЅС‹Рµ
        with self.assertRaises(AuthenticationError):
            gcm.decrypt(b"short", self.test_aad)

        # РќРµС‚ nonce РІ РґР°РЅРЅС‹С… (РјРµРЅСЊС€Рµ 12 Р±Р°Р№С‚)
        with self.assertRaises(AuthenticationError):
            gcm.decrypt(b"\x00" * 10, self.test_aad)

        # РќРµС‚ tag РІ РґР°РЅРЅС‹С… (СЂРѕРІРЅРѕ 12 Р±Р°Р№С‚ - С‚РѕР»СЊРєРѕ nonce)
        with self.assertRaises(AuthenticationError):
            gcm.decrypt(b"\x00" * 12, self.test_aad)

        print("вњ“ Error handling test passed")


def run_gcm_tests():
    """Р—Р°РїСѓСЃРє РІСЃРµС… GCM С‚РµСЃС‚РѕРІ"""
    print("=" * 60)
    print("Running GCM (Galois/Counter Mode) Tests")
    print("=" * 60)

    suite = unittest.TestLoader().loadTestsFromTestCase(TestGCM)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print(f"GCM Tests Summary: {result.testsRun} tests run")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 60)

    return result.wasSuccessful()


if __name__ == "__main__":
    # Р—Р°РїСѓСЃРє С‚РµСЃС‚РѕРІ СЃ РґРµС‚Р°Р»СЊРЅС‹Рј РІС‹РІРѕРґРѕРј
    run_gcm_tests()

