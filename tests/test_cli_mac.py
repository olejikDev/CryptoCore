#!/usr/bin/env python3
"""
РРЅС‚РµРіСЂР°С†РёРѕРЅРЅС‹Рµ С‚РµСЃС‚С‹ РґР»СЏ HMAC С‡РµСЂРµР· CLI
"""

import os
import subprocess
import tempfile
import unittest


class TestCLIMAC(unittest.TestCase):
    """РўРµСЃС‚С‹ HMAC С‡РµСЂРµР· CLI"""

    def setUp(self):
        """РќР°СЃС‚СЂРѕР№РєР° С‚РµСЃС‚РѕРІ"""
        # РЎРѕР·РґР°РµРј РІСЂРµРјРµРЅРЅСѓСЋ РґРёСЂРµРєС‚РѕСЂРёСЋ РґР»СЏ С‚РµСЃС‚РѕРІ
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")

        # Р—Р°РїРёСЃС‹РІР°РµРј С‚РµСЃС‚РѕРІС‹Рµ РґР°РЅРЅС‹Рµ
        with open(self.test_file, "w") as f:
            f.write("This is test data for HMAC testing.\n")
            f.write("Multiple lines to ensure proper hashing.\n")

    def tearDown(self):
        """РћС‡РёСЃС‚РєР° РїРѕСЃР»Рµ С‚РµСЃС‚РѕРІ"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def run_cryptocore(self, args):
        """Р—Р°РїСѓСЃРє cryptocore СЃ Р°СЂРіСѓРјРµРЅС‚Р°РјРё"""
        # РСЃРїРѕР»СЊР·СѓРµРј cryptocore.py РІ РєРѕСЂРЅРµ РїСЂРѕРµРєС‚Р°
        cmd = ["python", "cryptocore.py"] + args

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        return result

    def test_hmac_generation(self):
        """Р“РµРЅРµСЂР°С†РёСЏ HMAC С‡РµСЂРµР· CLI"""
        key = "00112233445566778899aabbccddeeff"

        result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file
        ])

        # РџСЂРѕРІРµСЂСЏРµРј, С‡С‚Рѕ РєРѕРјР°РЅРґР° РІС‹РїРѕР»РЅРёР»Р°СЃСЊ СѓСЃРїРµС€РЅРѕ
        self.assertEqual(result.returncode, 0)

        # РџСЂРѕРІРµСЂСЏРµРј С„РѕСЂРјР°С‚ РІС‹РІРѕРґР°
        output_lines = result.stdout.strip().split('\n')
        self.assertTrue(len(output_lines) > 0)

        # HMAC РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ hex СЃС‚СЂРѕРєРѕР№ + РёРјСЏ С„Р°Р№Р»Р°
        hmac_line = output_lines[0]
        hmac_parts = hmac_line.split()
        self.assertEqual(len(hmac_parts), 2)

        # РџСЂРѕРІРµСЂСЏРµРј С‡С‚Рѕ HMAC - hex СЃС‚СЂРѕРєР° (64 СЃРёРјРІРѕР»Р° РґР»СЏ SHA-256)
        hmac_hex = hmac_parts[0]
        self.assertEqual(len(hmac_hex), 64)

        # РџСЂРѕРІРµСЂСЏРµРј С‡С‚Рѕ РёРјСЏ С„Р°Р№Р»Р° РїСЂР°РІРёР»СЊРЅРѕРµ
        self.assertEqual(hmac_parts[1], self.test_file)

    def test_hmac_generation_with_output(self):
        """Р“РµРЅРµСЂР°С†РёСЏ HMAC СЃ Р·Р°РїРёСЃСЊСЋ РІ С„Р°Р№Р»"""
        key = "00112233445566778899aabbccddeeff"
        hmac_file = os.path.join(self.temp_dir, "test.hmac")

        result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file,
            "--output", hmac_file
        ])

        self.assertEqual(result.returncode, 0)

        # РџСЂРѕРІРµСЂСЏРµРј С‡С‚Рѕ С„Р°Р№Р» СЃРѕР·РґР°РЅ
        self.assertTrue(os.path.exists(hmac_file))

        # Р§РёС‚Р°РµРј С„Р°Р№Р» Рё РїСЂРѕРІРµСЂСЏРµРј С„РѕСЂРјР°С‚
        with open(hmac_file, 'r') as f:
            hmac_content = f.read().strip()

        hmac_parts = hmac_content.split()
        self.assertEqual(len(hmac_parts), 2)
        self.assertEqual(len(hmac_parts[0]), 64)  # SHA-256 hex РґР»РёРЅР°

    def test_hmac_verification_success(self):
        """РЈСЃРїРµС€РЅР°СЏ РїСЂРѕРІРµСЂРєР° HMAC"""
        key = "00112233445566778899aabbccddeeff"

        # РЎРЅР°С‡Р°Р»Р° РіРµРЅРµСЂРёСЂСѓРµРј HMAC
        hmac_file = os.path.join(self.temp_dir, "test.hmac")
        gen_result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file,
            "--output", hmac_file
        ])

        self.assertEqual(gen_result.returncode, 0)

        # РўРµРїРµСЂСЊ РїСЂРѕРІРµСЂСЏРµРј
        verify_result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file,
            "--verify", hmac_file
        ])

        # РџСЂРѕРІРµСЂРєР° РґРѕР»Р¶РЅР° РїСЂРѕР№С‚Рё СѓСЃРїРµС€РЅРѕ
        self.assertEqual(verify_result.returncode, 0)
        self.assertIn("verification successful", verify_result.stdout.lower())

    def test_hmac_verification_failure(self):
        """РќРµСѓСЃРїРµС€РЅР°СЏ РїСЂРѕРІРµСЂРєР° HMAC (РёР·РјРµРЅРµРЅРЅС‹Р№ С„Р°Р№Р»)"""
        key = "00112233445566778899aabbccddeeff"

        # РЎРѕР·РґР°РµРј HMAC РґР»СЏ РѕСЂРёРіРёРЅР°Р»СЊРЅРѕРіРѕ С„Р°Р№Р»Р°
        hmac_file = os.path.join(self.temp_dir, "test.hmac")
        self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file,
            "--output", hmac_file
        ])

        # РР·РјРµРЅСЏРµРј С„Р°Р№Р»
        with open(self.test_file, 'a') as f:
            f.write("\nTampered!")

        # РџС‹С‚Р°РµРјСЃСЏ РїСЂРѕРІРµСЂРёС‚СЊ СЃ РёР·РјРµРЅРµРЅРЅС‹Рј С„Р°Р№Р»РѕРј
        verify_result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key,
            "--input", self.test_file,
            "--verify", hmac_file
        ])

        # РџСЂРѕРІРµСЂРєР° РґРѕР»Р¶РЅР° РїСЂРѕРІР°Р»РёС‚СЊСЃСЏ
        self.assertNotEqual(verify_result.returncode, 0)
        self.assertIn("verification failed", verify_result.stderr.lower())

    def test_hmac_wrong_key(self):
        """РџСЂРѕРІРµСЂРєР° СЃ РЅРµРїСЂР°РІРёР»СЊРЅС‹Рј РєР»СЋС‡РѕРј"""
        key1 = "00112233445566778899aabbccddeeff"
        key2 = "ffeeccbbaa99887766554433221100ff"

        # Р“РµРЅРµСЂРёСЂСѓРµРј HMAC СЃ РїРµСЂРІС‹Рј РєР»СЋС‡РѕРј
        hmac_file = os.path.join(self.temp_dir, "test.hmac")
        self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key1,
            "--input", self.test_file,
            "--output", hmac_file
        ])

        # РџС‹С‚Р°РµРјСЃСЏ РїСЂРѕРІРµСЂРёС‚СЊ СЃ РґСЂСѓРіРёРј РєР»СЋС‡РѕРј
        verify_result = self.run_cryptocore([
            "dgst",
            "--algorithm", "sha256",
            "--hmac",
            "--key", key2,
            "--input", self.test_file,
            "--verify", hmac_file
        ])

        # РџСЂРѕРІРµСЂРєР° РґРѕР»Р¶РЅР° РїСЂРѕРІР°Р»РёС‚СЊСЃСЏ
        self.assertNotEqual(verify_result.returncode, 0)


if __name__ == "__main__":
    print("Running CLI MAC tests...")
    unittest.main(verbosity=2)

