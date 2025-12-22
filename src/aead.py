import os
import hmac
import hashlib


class AuthenticationError(Exception):
    """РСЃРєР»СЋС‡РµРЅРёРµ РґР»СЏ РѕС€РёР±РѕРє Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё"""
    pass


class EncryptThenMAC:
    """Р РµР°Р»РёР·Р°С†РёСЏ РїР°С‚С‚РµСЂРЅР° Encrypt-then-MAC"""

    def __init__(self, enc_key, mac_key, cipher_mode='ctr', hash_algo='sha256'):
        """
        РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ Encrypt-then-MAC

        Args:
            enc_key (bytes): РљР»СЋС‡ РґР»СЏ С€РёС„СЂРѕРІР°РЅРёСЏ
            mac_key (bytes): РљР»СЋС‡ РґР»СЏ MAC
            cipher_mode (str): Р РµР¶РёРј С€РёС„СЂРѕРІР°РЅРёСЏ ('ctr', 'cbc', etc.)
            hash_algo (str): РђР»РіРѕСЂРёС‚Рј С…СЌС€РёСЂРѕРІР°РЅРёСЏ РґР»СЏ HMAC
        """
        self.enc_key = enc_key
        self.mac_key = mac_key
        self.cipher_mode = cipher_mode
        self.hash_algo = hash_algo

        # РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ HMAC
        try:
            from src.mac.hmac import HMAC as CustomHMAC
            self.hmac = CustomHMAC(mac_key, hash_algo)
        except ImportError:
            # Fallback to built-in HMAC
            import hashlib
            self.hmac = hashlib

    def encrypt(self, plaintext, aad=b""):
        """
        РЁРёС„СЂРѕРІР°РЅРёРµ СЃ РїРѕСЃР»РµРґСѓСЋС‰РёРј РІС‹С‡РёСЃР»РµРЅРёРµРј MAC

        Args:
            plaintext (bytes): Р”Р°РЅРЅС‹Рµ РґР»СЏ С€РёС„СЂРѕРІР°РЅРёСЏ
            aad (bytes): РђСЃСЃРѕС†РёРёСЂРѕРІР°РЅРЅС‹Рµ РґР°РЅРЅС‹Рµ

        Returns:
            bytes: IV/nonce + ciphertext + tag
        """
        if self.cipher_mode == 'ctr':
            from src.modes.ctr import CTRMode
            cipher = CTRMode(self.enc_key)

            # CTR.encrypt() РІРѕР·РІСЂР°С‰Р°РµС‚ iv + ciphertext
            iv_and_ciphertext = cipher.encrypt(plaintext)

            # Р Р°Р·РґРµР»СЏРµРј РЅР° iv Рё ciphertext
            iv = iv_and_ciphertext[:16]  # 8 Р±Р°Р№С‚ nonce + 8 Р±Р°Р№С‚ counter
            ciphertext = iv_and_ciphertext[16:]
        else:
            raise ValueError(f"Р РµР¶РёРј {self.cipher_mode} РїРѕРєР° РЅРµ РїРѕРґРґРµСЂР¶РёРІР°РµС‚СЃСЏ")

        # Р’С‹С‡РёСЃР»РµРЅРёРµ MAC РЅР°Рґ ciphertext || aad
        mac_data = ciphertext + aad

        if hasattr(self.hmac, 'compute'):
            # Custom HMAC
            tag = self.hmac.compute(mac_data)
            tag_bytes = tag
        else:
            # Built-in HMAC
            hmac_obj = hmac.new(self.mac_key, mac_data, hashlib.sha256)
            tag_bytes = hmac_obj.digest()

        return iv + ciphertext + tag_bytes

    def decrypt(self, data, aad=b""):
        """
        Р Р°СЃС€РёС„СЂРѕРІР°РЅРёРµ СЃ РїСЂРѕРІРµСЂРєРѕР№ MAC

        Args:
            data (bytes): IV/nonce + ciphertext + tag
            aad (bytes): РђСЃСЃРѕС†РёРёСЂРѕРІР°РЅРЅС‹Рµ РґР°РЅРЅС‹Рµ

        Returns:
            bytes: Р Р°СЃС€РёС„СЂРѕРІР°РЅРЅС‹Р№ С‚РµРєСЃС‚

        Raises:
            AuthenticationError: Р•СЃР»Рё РїСЂРѕРІРµСЂРєР° MAC РЅРµ СѓРґР°Р»Р°СЃСЊ
        """
        if len(data) < 16 + 32:  # minimum: iv(16) + tag(32)
            raise AuthenticationError("Р”Р°РЅРЅС‹Рµ СЃР»РёС€РєРѕРј РєРѕСЂРѕС‚РєРёРµ")

        # Р Р°Р·РґРµР»РµРЅРёРµ РґР°РЅРЅС‹С…
        iv = data[:16]
        tag = data[-32:]  # SHA-256 РґР°РµС‚ 32-Р±Р°Р№С‚РЅС‹Р№ С…СЌС€
        ciphertext = data[16:-32]

        # РџСЂРѕРІРµСЂРєР° MAC
        mac_data = ciphertext + aad

        if hasattr(self.hmac, 'compute'):
            # Custom HMAC
            expected_tag = self.hmac.compute(mac_data)
            expected_tag_bytes = expected_tag
        else:
            # Built-in HMAC
            hmac_obj = hmac.new(self.mac_key, mac_data, hashlib.sha256)
            expected_tag_bytes = hmac_obj.digest()

        # РџРѕСЃС‚РѕСЏРЅРЅРѕРµ РїРѕ РІСЂРµРјРµРЅРё СЃСЂР°РІРЅРµРЅРёРµ
        if not self._constant_time_compare(tag, expected_tag_bytes):
            raise AuthenticationError("РћС€РёР±РєР° Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё: РЅРµРІРµСЂРЅС‹Р№ MAC")

        # Р Р°СЃС€РёС„СЂРѕРІР°РЅРёРµ
        if self.cipher_mode == 'ctr':
            from src.modes.ctr import CTRMode
            cipher = CTRMode(self.enc_key, iv)

            # Р’ CTR РјРµС‚РѕРґ decrypt РѕР¶РёРґР°РµС‚ iv + ciphertext
            encrypted_data = iv + ciphertext
            plaintext = cipher.decrypt(encrypted_data)
        else:
            raise ValueError(f"Р РµР¶РёРј {self.cipher_mode} РїРѕРєР° РЅРµ РїРѕРґРґРµСЂР¶РёРІР°РµС‚СЃСЏ")

        return plaintext

    @staticmethod
    def _constant_time_compare(a, b):
        """РЎСЂР°РІРЅРµРЅРёРµ СЃ РїРѕСЃС‚РѕСЏРЅРЅС‹Рј РІСЂРµРјРµРЅРµРј"""
        if len(a) != len(b):
            return False

        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    @staticmethod
    def derive_keys(master_key, salt=b""):
        """
        Р“РµРЅРµСЂР°С†РёСЏ РѕС‚РґРµР»СЊРЅС‹С… РєР»СЋС‡РµР№ РґР»СЏ С€РёС„СЂРѕРІР°РЅРёСЏ Рё MAC РёР· РјР°СЃС‚РµСЂ-РєР»СЋС‡Р°

        Args:
            master_key (bytes): РСЃС…РѕРґРЅС‹Р№ РєР»СЋС‡
            salt (bytes): РЎРѕР»СЊ РґР»СЏ KDF

        Returns:
            tuple: (enc_key, mac_key)
        """
        # РџСЂРѕСЃС‚РѕР№ KDF РЅР° РѕСЃРЅРѕРІРµ HKDF-РїРѕРґРѕР±РЅРѕР№ СЃС…РµРјС‹
        hmac1 = hmac.new(master_key, b"encryption" + salt, hashlib.sha256).digest()
        hmac2 = hmac.new(master_key, b"authentication" + salt, hashlib.sha256).digest()

        # Р‘РµСЂРµРј РїРµСЂРІС‹Рµ 16 Р±Р°Р№С‚ РґР»СЏ AES-128
        enc_key = hmac1[:16]
        mac_key = hmac2

        return enc_key, mac_key


# Р”Р»СЏ РѕР±СЂР°С‚РЅРѕР№ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё
__all__ = ['EncryptThenMAC', 'AuthenticationError']

