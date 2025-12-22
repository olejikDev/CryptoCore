"""
Р РµР°Р»РёР·Р°С†РёСЏ HMAC (Hash-based Message Authentication Code)
РЎРѕРіР»Р°СЃРЅРѕ RFC 2104, РёСЃРїРѕР»СЊР·СѓРµС‚ SHA-256 РёР· Sprint 4
"""

import struct
from src.hash.sha256 import SHA256


class HMAC:
    """Р РµР°Р»РёР·Р°С†РёСЏ HMAC СЃ РїРѕРґРґРµСЂР¶РєРѕР№ РєР»СЋС‡РµР№ РїРµСЂРµРјРµРЅРЅРѕР№ РґР»РёРЅС‹"""

    BLOCK_SIZE = 64  # Р Р°Р·РјРµСЂ Р±Р»РѕРєР° РґР»СЏ SHA-256 (РІ Р±Р°Р№С‚Р°С…)

    def __init__(self, key, hash_algorithm='sha256'):
        """
        РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ HMAC

        Args:
            key: РєР»СЋС‡ РІ РІРёРґРµ bytes РёР»Рё hex СЃС‚СЂРѕРєРё
            hash_algorithm: РёСЃРїРѕР»СЊР·СѓРµРјР°СЏ С…РµС€-С„СѓРЅРєС†РёСЏ (РїРѕРґРґРµСЂР¶РёРІР°РµС‚СЃСЏ С‚РѕР»СЊРєРѕ sha256)
        """
        if isinstance(key, str):
            # РџСЂРµРѕР±СЂР°Р·СѓРµРј hex СЃС‚СЂРѕРєСѓ РІ bytes
            self.key = bytes.fromhex(key)
        else:
            self.key = key

        self.hash_algorithm = hash_algorithm.lower()

        if self.hash_algorithm != 'sha256':
            raise ValueError(f"РќРµРїРѕРґРґРµСЂР¶РёРІР°РµРјС‹Р№ Р°Р»РіРѕСЂРёС‚Рј: {self.hash_algorithm}")

        # РћРїСЂРµРґРµР»СЏРµРј С…РµС€-РєР»Р°СЃСЃ
        self.hash_class = SHA256

        # РћР±СЂР°Р±РѕС‚РєР° РєР»СЋС‡Р° СЃРѕРіР»Р°СЃРЅРѕ RFC 2104
        self._process_key()

        # Р’С‹С‡РёСЃР»СЏРµРј ipad Рё opad
        self.ipad = bytes(x ^ 0x36 for x in self.key)
        self.opad = bytes(x ^ 0x5c for x in self.key)

        # РРЅРёС†РёР°Р»РёР·РёСЂСѓРµРј С…РµС€-РѕР±СЉРµРєС‚
        self.inner_hash = None
        self.outer_hash = None

    def _process_key(self):
        """РћР±СЂР°Р±РѕС‚РєР° РєР»СЋС‡Р° СЃРѕРіР»Р°СЃРЅРѕ RFC 2104"""
        key_len = len(self.key)

        # 1. Р•СЃР»Рё РєР»СЋС‡ РґР»РёРЅРЅРµРµ СЂР°Р·РјРµСЂР° Р±Р»РѕРєР°, С…РµС€РёСЂСѓРµРј РµРіРѕ
        if key_len > self.BLOCK_SIZE:
            # РЎРѕР·РґР°РµРј РЅРѕРІС‹Р№ СЌРєР·РµРјРїР»СЏСЂ SHA256 РґР»СЏ С…РµС€РёСЂРѕРІР°РЅРёСЏ РєР»СЋС‡Р°
            hash_obj = self.hash_class()
            hash_obj.update(self.key)
            self.key = hash_obj.digest()
            key_len = len(self.key)

        # 2. Р•СЃР»Рё РєР»СЋС‡ РєРѕСЂРѕС‡Рµ СЂР°Р·РјРµСЂР° Р±Р»РѕРєР°, РґРѕРїРѕР»РЅСЏРµРј РЅСѓР»СЏРјРё
        if key_len < self.BLOCK_SIZE:
            self.key += b'\x00' * (self.BLOCK_SIZE - key_len)

    def reset(self):
        """РЎР±СЂРѕСЃ СЃРѕСЃС‚РѕСЏРЅРёСЏ HMAC РґР»СЏ РЅРѕРІРѕРіРѕ СЃРѕРѕР±С‰РµРЅРёСЏ"""
        self.inner_hash = None
        self.outer_hash = None

    def update(self, data):
        """
        Р”РѕР±Р°РІР»РµРЅРёРµ РґР°РЅРЅС‹С… РґР»СЏ HMAC (РёРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕРµ)

        Args:
            data: РґР°РЅРЅС‹Рµ РґР»СЏ РґРѕР±Р°РІР»РµРЅРёСЏ (bytes)
        """
        if not isinstance(data, bytes):
            raise TypeError("Р”Р°РЅРЅС‹Рµ РґРѕР»Р¶РЅС‹ Р±С‹С‚СЊ РІ С„РѕСЂРјР°С‚Рµ bytes")

        # Р•СЃР»Рё СЌС‚Рѕ РїРµСЂРІС‹Р№ РІС‹Р·РѕРІ update, РЅР°С‡РёРЅР°РµРј РІС‹С‡РёСЃР»РµРЅРёРµ inner hash
        if self.inner_hash is None:
            self.inner_hash = self.hash_class()
            self.inner_hash.update(self.ipad)

        # Р”РѕР±Р°РІР»СЏРµРј РґР°РЅРЅС‹Рµ Рє inner hash
        self.inner_hash.update(data)

    def finalize(self):
        """Р—Р°РІРµСЂС€РµРЅРёРµ РІС‹С‡РёСЃР»РµРЅРёСЏ HMAC Рё РІРѕР·РІСЂР°С‚ СЂРµР·СѓР»СЊС‚Р°С‚Р°"""
        # Р•СЃР»Рё update РЅРµ РІС‹Р·С‹РІР°Р»СЃСЏ, inner_hash Р±СѓРґРµС‚ None
        if self.inner_hash is None:
            # РЎРѕР·РґР°РµРј inner hash СЃ ipad
            self.inner_hash = self.hash_class()
            self.inner_hash.update(self.ipad)

        # РџРѕР»СѓС‡Р°РµРј РІРЅСѓС‚СЂРµРЅРЅРёР№ С…РµС€
        inner_hash_digest = self.inner_hash.digest()

        # Р’С‹С‡РёСЃР»СЏРµРј РІРЅРµС€РЅРёР№ С…РµС€: hash(opad || inner_hash)
        self.outer_hash = self.hash_class()
        self.outer_hash.update(self.opad)
        self.outer_hash.update(inner_hash_digest)

        return self.outer_hash.digest()

    def compute(self, message):
        """
        Р’С‹С‡РёСЃР»РµРЅРёРµ HMAC РґР»СЏ СЃРѕРѕР±С‰РµРЅРёСЏ

        Args:
            message: СЃРѕРѕР±С‰РµРЅРёРµ (bytes РёР»Рё str)

        Returns:
            bytes: HMAC РІ Р±РёРЅР°СЂРЅРѕРј С„РѕСЂРјР°С‚Рµ
        """
        if isinstance(message, str):
            message = message.encode('utf-8')

        self.reset()
        self.update(message)
        return self.finalize()

    def hexdigest(self, message=None):
        """
        РџРѕР»СѓС‡РµРЅРёРµ HMAC РІ hex С„РѕСЂРјР°С‚Рµ

        Args:
            message: РѕРїС†РёРѕРЅР°Р»СЊРЅРѕРµ СЃРѕРѕР±С‰РµРЅРёРµ РґР»СЏ РІС‹С‡РёСЃР»РµРЅРёСЏ

        Returns:
            str: HMAC РІ hex С„РѕСЂРјР°С‚Рµ
        """
        if message is not None:
            hmac_bytes = self.compute(message)
        else:
            hmac_bytes = self.finalize()

        return hmac_bytes.hex()

    def verify(self, message, expected_hmac):
        """
        РџСЂРѕРІРµСЂРєР° HMAC

        Args:
            message: СЃРѕРѕР±С‰РµРЅРёРµ РґР»СЏ РїСЂРѕРІРµСЂРєРё
            expected_hmac: РѕР¶РёРґР°РµРјС‹Р№ HMAC (bytes РёР»Рё hex СЃС‚СЂРѕРєР°)

        Returns:
            bool: True РµСЃР»Рё HMAC СЃРѕРІРїР°РґР°РµС‚
        """
        if isinstance(expected_hmac, str):
            expected_hmac = bytes.fromhex(expected_hmac)

        computed_hmac = self.compute(message)
        return computed_hmac == expected_hmac


def compute_hmac(key, message, hash_algo='sha256'):
    """
    РЈРїСЂРѕС‰РµРЅРЅР°СЏ С„СѓРЅРєС†РёСЏ РґР»СЏ РІС‹С‡РёСЃР»РµРЅРёСЏ HMAC

    Args:
        key: РєР»СЋС‡ (bytes РёР»Рё hex СЃС‚СЂРѕРєР°)
        message: СЃРѕРѕР±С‰РµРЅРёРµ (bytes РёР»Рё str)
        hash_algo: Р°Р»РіРѕСЂРёС‚Рј С…РµС€РёСЂРѕРІР°РЅРёСЏ

    Returns:
        str: HMAC РІ hex С„РѕСЂРјР°С‚Рµ
    """
    hmac = HMAC(key, hash_algo)
    return hmac.hexdigest(message)

