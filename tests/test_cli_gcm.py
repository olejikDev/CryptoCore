#!/usr/bin/env python3
"""
РРЅС‚РµРіСЂР°С†РёРѕРЅРЅС‹Рµ С‚РµСЃС‚С‹ РґР»СЏ CLI СЃ GCM
"""

import os
import subprocess
import tempfile
import unittest


class TestCLIGCM(unittest.TestCase):
    """РўРµСЃС‚С‹ CLI СЃ GCM СЂРµР¶РёРјРѕРј"""

    def setUp(self):
        """РќР°СЃС‚СЂРѕР№РєР° С‚РµСЃС‚РѕРІ"""
        self.test_data = b"Test data for CLI GCM testing"
        self.key = "00112233445566778899aabbccddeeff"
        self.aad = "aabbccddeeff00112233445566778899"

    def run_command(self, cmd):
        """Р—Р°РїСѓСЃРє РєРѕРјР°РЅРґС‹ Рё РІРѕР·РІСЂР°С‚ СЂРµР·СѓР»СЊС‚Р°С‚Р°"""
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True
        )
        return result.returncode, result.stdout, result.stderr

    def test_cli_gcm_encrypt_decrypt(self):
        """РўРµСЃС‚ CLI: GCM С€РёС„СЂРѕРІР°РЅРёРµ Рё СЂР°СЃС€РёС„СЂРѕРІР°РЅРёРµ"""
        print("\n=== Test 1: CLI GCM encryption/decryption ===")

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as plain_file:
            plain_file.write(self.test_data)
            plain_path = plain_file.name

        encrypted_path = plain_path + '.enc'
        decrypted_path = plain_path + '.dec'

        try:
            # 1. РЁРёС„СЂРѕРІР°РЅРёРµ
            cmd = f"python cryptocore.py --algorithm aes --mode gcm --encrypt \
                  --key {self.key} --input {plain_path} --output {encrypted_path} \
                  --aad {self.aad}"

            returncode, stdout, stderr = self.run_command(cmd)
            print(f"Encryption command: {cmd}")
            print(f"Return code: {returncode}")
            print(f"Stdout: {stdout}")
            print(f"Stderr: {stderr}")

            self.assertEqual(returncode, 0, f"Encryption failed: {stderr}")
            self.assertTrue(os.path.exists(encrypted_path))

            # 2. Р”РµС€РёС„СЂРѕРІР°РЅРёРµ
            cmd = f"python cryptocore.py --algorithm aes --mode gcm --decrypt \
                  --key {self.key} --input {encrypted_path} --output {decrypted_path} \
                  --aad {self.aad}"

            returncode, stdout, stderr = self.run_command(cmd)
            print(f"\nDecryption command: {cmd}")
            print(f"Return code: {returncode}")
            print(f"Stdout: {stdout}")
            print(f"Stderr: {stderr}")

            self.assertEqual(returncode, 0, f"Decryption failed: {stderr}")
            self.assertTrue(os.path.exists(decrypted_path))

            # 3. РџСЂРѕРІРµСЂРєР° РґР°РЅРЅС‹С…
            with open(decrypted_path, 'rb') as f:
                decrypted_data = f.read()

            self.assertEqual(decrypted_data, self.test_data)
            print("вњ“ CLI GCM encryption/decryption test passed")

        finally:
            # РћС‡РёСЃС‚РєР°
            for path in [plain_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.remove(path)

    def test_cli_gcm_auth_failure(self):
        """РўРµСЃС‚ CLI: РЅРµСѓРґР°С‡Р° Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё GCM"""
        print("\n=== Test 2: CLI GCM authentication failure ===")

        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as plain_file:
            plain_file.write(self.test_data)
            plain_path = plain_file.name

        encrypted_path = plain_path + '.enc'
        decrypted_path = plain_path + '.dec'

        try:
            # 1. РЁРёС„СЂРѕРІР°РЅРёРµ СЃ РїСЂР°РІРёР»СЊРЅС‹Рј AAD
            cmd = f"python cryptocore.py --algorithm aes --mode gcm --encrypt \
                  --key {self.key} --input {plain_path} --output {encrypted_path} \
                  --aad {self.aad}"

            self.run_command(cmd)

            # 2. РџСЂРѕР±СѓРµРј РґРµС€РёС„СЂРѕРІР°С‚СЊ СЃ РЅРµРїСЂР°РІРёР»СЊРЅС‹Рј AAD
            wrong_aad = "ffffffffffffffffffffffffffffffff"
            cmd = f"python cryptocore.py --algorithm aes --mode gcm --decrypt \
                  --key {self.key} --input {encrypted_path} --output {decrypted_path} \
                  --aad {wrong_aad}"

            returncode, stdout, stderr = self.run_command(cmd)

            # Р”РѕР»Р¶РµРЅ Р±С‹С‚СЊ РЅРµРЅСѓР»РµРІРѕР№ РєРѕРґ РІРѕР·РІСЂР°С‚Р° РїСЂРё РЅРµСѓРґР°С‡РЅРѕР№ Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё
            self.assertNotEqual(returncode, 0,
                                "Should fail with wrong AAD but didn't")

            # Р¤Р°Р№Р» РЅРµ РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ СЃРѕР·РґР°РЅ
            self.assertFalse(os.path.exists(decrypted_path),
                             "Output file should not be created on auth failure")

            print("вњ“ CLI GCM authentication failure test passed")

        finally:
            # РћС‡РёСЃС‚РєР°
            for path in [plain_path, encrypted_path, decrypted_path]:
                if os.path.exists(path):
                    os.remove(path)


if __name__ == "__main__":
    print("Running CLI GCM tests...")
    unittest.main(verbosity=2)

