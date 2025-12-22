"""
Р РµР°Р»РёР·Р°С†РёСЏ СЂРµР¶РёРјР° Counter (CTR) РґР»СЏ AES
РЎ Р РЈР§РќРћР™ СЂРµР°Р»РёР·Р°С†РёРµР№ counter РјРµС…Р°РЅРёР·РјР° (С‚СЂРµР±РѕРІР°РЅРёРµ CRY-2 Sprint 2)
"""

from Crypto.Cipher import AES
from src.csprng import generate_random_bytes


class CTRMode:
    """РљР»Р°СЃСЃ РґР»СЏ СЂР°Р±РѕС‚С‹ СЃ СЂРµР¶РёРјРѕРј CTR СЃ СЂСѓС‡РЅРѕР№ СЂРµР°Р»РёР·Р°С†РёРµР№ counter"""

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
            self.nonce = iv[:8]  # РџРµСЂРІС‹Рµ 8 Р±Р°Р№С‚ - nonce
            self.counter = int.from_bytes(iv[8:], 'big')  # РџРѕСЃР»РµРґРЅРёРµ 8 Р±Р°Р№С‚ - СЃС‡РµС‚С‡РёРє
        else:
            # РСЃРїРѕР»СЊР·СѓРµРј CSPRNG РґР»СЏ РіРµРЅРµСЂР°С†РёРё nonce
            self.nonce = generate_random_bytes(8)
            self.counter = 0

    def _get_counter_bytes(self):
        """РџРѕР»СѓС‡РёС‚СЊ С‚РµРєСѓС‰РµРµ Р·РЅР°С‡РµРЅРёРµ СЃС‡РµС‚С‡РёРєР° РІ РІРёРґРµ Р±Р°Р№С‚РѕРІ"""
        return self.nonce + self.counter.to_bytes(8, 'big')

    def encrypt(self, plaintext):
        """РЁРёС„СЂРѕРІР°РЅРёРµ СЃ СЂСѓС‡РЅРѕР№ СЂРµР°Р»РёР·Р°С†РёРµР№ CTR"""
        if not plaintext:
            raise ValueError("РќРµР»СЊР·СЏ С€РёС„СЂРѕРІР°С‚СЊ РїСѓСЃС‚С‹Рµ РґР°РЅРЅС‹Рµ")

        ciphertext = b""
        current_counter = self.counter

        # РЁРёС„СЂСѓРµРј РґР°РЅРЅС‹Рµ
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # 1. РџРѕР»СѓС‡Р°РµРј С‚РµРєСѓС‰РµРµ Р·РЅР°С‡РµРЅРёРµ СЃС‡РµС‚С‡РёРєР°
            counter_bytes = self.nonce + current_counter.to_bytes(8, 'big')

            # 2. РЁРёС„СЂСѓРµРј СЃС‡РµС‚С‡РёРє РґР»СЏ РїРѕР»СѓС‡РµРЅРёСЏ keystream
            keystream_block = self.aes_primitive.encrypt(counter_bytes)

            # 3. XOR plaintext СЃ keystream
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            ciphertext += encrypted_block

            # 4. РРЅРєСЂРµРјРµРЅС‚РёСЂСѓРµРј СЃС‡РµС‚С‡РёРє
            current_counter += 1

        # РЎРѕС…СЂР°РЅСЏРµРј РЅР°С‡Р°Р»СЊРЅС‹Р№ counter РґР»СЏ IV
        iv = self.nonce + self.counter.to_bytes(8, 'big')
        return iv + ciphertext

    def decrypt(self, data, remove_padding=False):  # Р”РѕР±Р°РІР»СЏРµРј remove_padding РґР»СЏ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё
        """Р”РµС€РёС„СЂРѕРІР°РЅРёРµ CTR (С‚Р°РєРѕРµ Р¶Рµ РєР°Рє С€РёС„СЂРѕРІР°РЅРёРµ)"""
        if not data:
            raise ValueError("РќРµР»СЊР·СЏ РґРµС€РёС„СЂРѕРІР°С‚СЊ РїСѓСЃС‚С‹Рµ РґР°РЅРЅС‹Рµ")

        if len(data) < self.block_size:
            raise ValueError(f"Р”Р°РЅРЅС‹Рµ СЃР»РёС€РєРѕРј РєРѕСЂРѕС‚РєРёРµ РґР»СЏ CTR СЂРµР¶РёРјР°. РњРёРЅРёРјСѓРј {self.block_size} Р±Р°Р№С‚ (nonce+counter)")

        # РР·РІР»РµРєР°РµРј nonce Рё РЅР°С‡Р°Р»СЊРЅС‹Р№ СЃС‡РµС‚С‡РёРє
        iv = data[:16]
        nonce = iv[:8]
        initial_counter = int.from_bytes(iv[8:], 'big')
        ciphertext = data[16:]

        plaintext = b""
        current_counter = initial_counter

        # Р”РµС€РёС„СЂСѓРµРј РґР°РЅРЅС‹Рµ
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 1. РџРѕР»СѓС‡Р°РµРј С‚РµРєСѓС‰РµРµ Р·РЅР°С‡РµРЅРёРµ СЃС‡РµС‚С‡РёРєР°
            counter_bytes = nonce + current_counter.to_bytes(8, 'big')

            # 2. РЁРёС„СЂСѓРµРј СЃС‡РµС‚С‡РёРє РґР»СЏ РїРѕР»СѓС‡РµРЅРёСЏ keystream
            keystream_block = self.aes_primitive.encrypt(counter_bytes)

            # 3. XOR ciphertext СЃ keystream
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            plaintext += decrypted_block

            # 4. РРЅРєСЂРµРјРµРЅС‚РёСЂСѓРµРј СЃС‡РµС‚С‡РёРє
            current_counter += 1

        # CTR - РїРѕС‚РѕРєРѕРІС‹Р№ СЂРµР¶РёРј, padding РЅРµ РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ
        # remove_padding РёРіРЅРѕСЂРёСЂСѓРµС‚СЃСЏ, РЅРѕ РїР°СЂР°РјРµС‚СЂ РѕСЃС‚Р°РІР»РµРЅ РґР»СЏ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё
        return plaintext


# ===== Р”РћР‘РђР’РРўР¬ Р­РўРћ Р’ РљРћРќР•Р¦ Р¤РђР™Р›Рђ =====
CTR = CTRMode  # РџСЃРµРІРґРѕРЅРёРј РґР»СЏ РѕР±СЂР°С‚РЅРѕР№ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё

__all__ = ['CTRMode', 'CTR']

