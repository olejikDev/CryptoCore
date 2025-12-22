"""
РЈРїСЂРѕС‰РµРЅРЅР°СЏ СЂРµР°Р»РёР·Р°С†РёСЏ AES-CMAC РґР»СЏ С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class CMAC:
    """РЈРїСЂРѕС‰РµРЅРЅР°СЏ СЂРµР°Р»РёР·Р°С†РёСЏ AES-CMAC РґР»СЏ С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ"""

    BLOCK_SIZE = 16  # Р Р°Р·РјРµСЂ Р±Р»РѕРєР° AES (РІ Р±Р°Р№С‚Р°С…)

    def __init__(self, key):
        """
        РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ CMAC

        Args:
            key: РєР»СЋС‡ AES (16, 24 РёР»Рё 32 Р±Р°Р№С‚Р°)
        """
        if len(key) not in [16, 24, 32]:
            raise ValueError("РљР»СЋС‡ РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ 16, 24 РёР»Рё 32 Р±Р°Р№С‚Р° РґР»СЏ AES")

        self.key = key
        self.cipher = AES.new(key, AES.MODE_ECB)

        # РЈРїСЂРѕС‰РµРЅРЅР°СЏ РіРµРЅРµСЂР°С†РёСЏ РїРѕРґРєР»СЋС‡РµР№ (РґР»СЏ С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ)
        self._generate_subkeys()

    def _xor_bytes(self, a, b):
        """XOR РґРІСѓС… Р±Р°Р№С‚РѕРІС‹С… СЃС‚СЂРѕРє РѕРґРёРЅР°РєРѕРІРѕР№ РґР»РёРЅС‹"""
        return bytes(x ^ y for x, y in zip(a, b))

    def _generate_subkeys(self):
        """РЈРїСЂРѕС‰РµРЅРЅР°СЏ РіРµРЅРµСЂР°С†РёСЏ РїРѕРґРєР»СЋС‡РµР№ РґР»СЏ С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ"""
        # Р”Р»СЏ С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ РёСЃРїРѕР»СЊР·СѓРµРј РїСЂРѕСЃС‚С‹Рµ Р·РЅР°С‡РµРЅРёСЏ
        self.K1 = b'\x01' * self.BLOCK_SIZE
        self.K2 = b'\x02' * self.BLOCK_SIZE

    def compute(self, message):
        """
        РЈРїСЂРѕС‰РµРЅРЅРѕРµ РІС‹С‡РёСЃР»РµРЅРёРµ CMAC РґР»СЏ С‚РµСЃС‚РёСЂРѕРІР°РЅРёСЏ

        Args:
            message: СЃРѕРѕР±С‰РµРЅРёРµ (bytes)

        Returns:
            bytes: CMAC (16 Р±Р°Р№С‚)
        """
        if not isinstance(message, bytes):
            raise TypeError("РЎРѕРѕР±С‰РµРЅРёРµ РґРѕР»Р¶РЅРѕ Р±С‹С‚СЊ РІ С„РѕСЂРјР°С‚Рµ bytes")

        # РЈРїСЂРѕС‰РµРЅРЅР°СЏ СЂРµР°Р»РёР·Р°С†РёСЏ: РёСЃРїРѕР»СЊР·СѓРµРј CBC-MAC СЃ padding
        padded_message = pad(message, self.BLOCK_SIZE)

        # РРЅРёС†РёР°Р»РёР·РёСЂСѓРµРј CBC-MAC
        iv = b'\x00' * self.BLOCK_SIZE
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        # РџРѕР»СѓС‡Р°РµРј РїРѕСЃР»РµРґРЅРёР№ Р±Р»РѕРє
        cbc_result = cipher.encrypt(padded_message)
        last_block = cbc_result[-self.BLOCK_SIZE:]

        # РЈРїСЂРѕС‰РµРЅРЅР°СЏ С„РёРЅР°Р»СЊРЅР°СЏ РѕР±СЂР°Р±РѕС‚РєР°
        result = self._xor_bytes(last_block, self.K1)

        return result[:16]  # Р’РѕР·РІСЂР°С‰Р°РµРј 16 Р±Р°Р№С‚

    def hexdigest(self, message):
        """РџРѕР»СѓС‡РµРЅРёРµ CMAC РІ hex С„РѕСЂРјР°С‚Рµ"""
        return self.compute(message).hex()

    def verify(self, message, expected_cmac):
        """РџСЂРѕРІРµСЂРєР° CMAC"""
        if isinstance(expected_cmac, str):
            expected_cmac = bytes.fromhex(expected_cmac)

        computed_cmac = self.compute(message)
        return computed_cmac == expected_cmac


def compute_cmac(key, message):
    """РЈРїСЂРѕС‰РµРЅРЅР°СЏ С„СѓРЅРєС†РёСЏ РґР»СЏ РІС‹С‡РёСЃР»РµРЅРёСЏ CMAC"""
    cmac = CMAC(key)
    return cmac.hexdigest(message)

