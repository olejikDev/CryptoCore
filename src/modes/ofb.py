"""
Р РµР°Р»РёР·Р°С†РёСЏ СЂРµР¶РёРјР° Output Feedback (OFB) РґР»СЏ AES
РЎ Р РЈР§РќРћР™ СЂРµР°Р»РёР·Р°С†РёРµР№ stream cipher (С‚СЂРµР±РѕРІР°РЅРёРµ CRY-2 Sprint 2)
"""

from Crypto.Cipher import AES
from src.csprng import generate_random_bytes


class OFBMode:
    """РљР»Р°СЃСЃ РґР»СЏ СЂР°Р±РѕС‚С‹ СЃ СЂРµР¶РёРјРѕРј OFB СЃ СЂСѓС‡РЅРѕР№ СЂРµР°Р»РёР·Р°С†РёРµР№"""

    def __init__(self, key, iv=None):
        if len(key) != 16:
            raise ValueError(f"РќРµРєРѕСЂСЂРµРєС‚РЅР°СЏ РґР»РёРЅР° РєР»СЋС‡Р°: {len(key)} Р±Р°Р№С‚. Р”Р»СЏ AES-128 С‚СЂРµР±СѓРµС‚СЃСЏ 16 Р±Р°Р№С‚.")

        self.key = key
        self.block_size = AES.block_size

        # РЎРѕР·РґР°РµРј AES РїСЂРёРјРёС‚РёРІ
        self.aes_primitive = AES.new(self.key, AES.MODE_ECB)

        if iv:
            if len(iv) != 16:
                raise ValueError(f"IV РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ 16 Р±Р°Р№С‚. РџРѕР»СѓС‡РµРЅРѕ: {len(iv)} Р±Р°Р№С‚")
            self.iv = iv
        else:
            # РСЃРїРѕР»СЊР·СѓРµРј CSPRNG РґР»СЏ РіРµРЅРµСЂР°С†РёРё IV
            self.iv = generate_random_bytes(16)

    def encrypt(self, plaintext):
        """РЁРёС„СЂРѕРІР°РЅРёРµ СЃ СЂСѓС‡РЅРѕР№ СЂРµР°Р»РёР·Р°С†РёРµР№ OFB (keystream РЅРµР·Р°РІРёСЃРёРј РѕС‚ plaintext)"""
        if not plaintext:
            raise ValueError("РќРµР»СЊР·СЏ С€РёС„СЂРѕРІР°С‚СЊ РїСѓСЃС‚С‹Рµ РґР°РЅРЅС‹Рµ")

        ciphertext = b""
        feedback = self.iv  # РќР°С‡РёРЅР°РµРј СЃ IV

        # Р“РµРЅРµСЂРёСЂСѓРµРј keystream Рё С€РёС„СЂСѓРµРј
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # 1. Р“РµРЅРµСЂРёСЂСѓРµРј keystream Р±Р»РѕРє (С€РёС„СЂСѓРµРј feedback)
            keystream_block = self.aes_primitive.encrypt(feedback)

            # 2. XOR plaintext СЃ keystream
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            ciphertext += encrypted_block

            # 3. РћР±РЅРѕРІР»СЏРµРј feedback РґР»СЏ СЃР»РµРґСѓСЋС‰РµРіРѕ Р±Р»РѕРєР° (keystream)
            feedback = keystream_block

        return self.iv + ciphertext

    def decrypt(self, data, remove_padding=False):  # Р”РѕР±Р°РІР»СЏРµРј remove_padding РґР»СЏ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё
        """Р”РµС€РёС„СЂРѕРІР°РЅРёРµ OFB (С‚Р°РєРѕРµ Р¶Рµ РєР°Рє С€РёС„СЂРѕРІР°РЅРёРµ)"""
        if not data:
            raise ValueError("РќРµР»СЊР·СЏ РґРµС€РёС„СЂРѕРІР°С‚СЊ РїСѓСЃС‚С‹Рµ РґР°РЅРЅС‹Рµ")

        if len(data) < self.block_size:
            raise ValueError(f"Р”Р°РЅРЅС‹Рµ СЃР»РёС€РєРѕРј РєРѕСЂРѕС‚РєРёРµ РґР»СЏ OFB СЂРµР¶РёРјР°. РњРёРЅРёРјСѓРј {self.block_size} Р±Р°Р№С‚ (IV)")

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

        plaintext = b""
        feedback = iv

        # Р“РµРЅРµСЂРёСЂСѓРµРј С‚РѕС‚ Р¶Рµ keystream Рё РґРµС€РёС„СЂСѓРµРј
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 1. Р“РµРЅРµСЂРёСЂСѓРµРј keystream Р±Р»РѕРє
            keystream_block = self.aes_primitive.encrypt(feedback)

            # 2. XOR ciphertext СЃ keystream
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            plaintext += decrypted_block

            # 3. РћР±РЅРѕРІР»СЏРµРј feedback
            feedback = keystream_block

        # OFB - РїРѕС‚РѕРєРѕРІС‹Р№ СЂРµР¶РёРј, padding РЅРµ РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ
        # remove_padding РёРіРЅРѕСЂРёСЂСѓРµС‚СЃСЏ, РЅРѕ РїР°СЂР°РјРµС‚СЂ РѕСЃС‚Р°РІР»РµРЅ РґР»СЏ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё
        return plaintext

