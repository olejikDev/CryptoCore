"""
Р РµР°Р»РёР·Р°С†РёСЏ СЂРµР¶РёРјР° Cipher Feedback (CFB) РґР»СЏ AES
РЎ Р РЈР§РќРћР™ СЂРµР°Р»РёР·Р°С†РёРµР№ stream cipher (С‚СЂРµР±РѕРІР°РЅРёРµ CRY-2 Sprint 2)
"""

from Crypto.Cipher import AES
from src.csprng import generate_random_bytes


class CFBMode:
    """РљР»Р°СЃСЃ РґР»СЏ СЂР°Р±РѕС‚С‹ СЃ СЂРµР¶РёРјРѕРј CFB СЃ СЂСѓС‡РЅРѕР№ СЂРµР°Р»РёР·Р°С†РёРµР№"""

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
        """РЁРёС„СЂРѕРІР°РЅРёРµ СЃ СЂСѓС‡РЅРѕР№ СЂРµР°Р»РёР·Р°С†РёРµР№ CFB (stream cipher)"""
        if not plaintext:
            raise ValueError("РќРµР»СЊР·СЏ С€РёС„СЂРѕРІР°С‚СЊ РїСѓСЃС‚С‹Рµ РґР°РЅРЅС‹Рµ")

        ciphertext = b""
        shift_register = self.iv  # РќР°С‡РёРЅР°РµРј СЃ IV

        # РћР±СЂР°Р±Р°С‚С‹РІР°РµРј РґР°РЅРЅС‹Рµ Р±Р»РѕРєР°РјРё
        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]

            # 1. РЁРёС„СЂСѓРµРј СЃРѕРґРµСЂР¶РёРјРѕРµ shift register
            keystream = self.aes_primitive.encrypt(shift_register)

            # 2. XOR СЃ plaintext РґР»СЏ РїРѕР»СѓС‡РµРЅРёСЏ ciphertext
            encrypted_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            ciphertext += encrypted_block

            # 3. РћР±РЅРѕРІР»СЏРµРј shift register
            # Р’ CFB shift register РѕР±РЅРѕРІР»СЏРµС‚СЃСЏ ciphertext Р±Р»РѕРєРѕРј, РґРѕРїРѕР»РЅРµРЅРЅС‹Рј РµСЃР»Рё РЅСѓР¶РЅРѕ
            if len(encrypted_block) == self.block_size:
                shift_register = encrypted_block
            else:
                # Р•СЃР»Рё Р±Р»РѕРє РЅРµ РїРѕР»РЅС‹Р№, РґРѕРїРѕР»РЅСЏРµРј РёР· РїСЂРµРґС‹РґСѓС‰РµРіРѕ shift register
                shift_register = encrypted_block + shift_register[len(encrypted_block):]

        return self.iv + ciphertext

    def decrypt(self, data, remove_padding=False):  # Р”РѕР±Р°РІР»СЏРµРј remove_padding РґР»СЏ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё
        """Р”РµС€РёС„СЂРѕРІР°РЅРёРµ СЃ СЂСѓС‡РЅРѕР№ СЂРµР°Р»РёР·Р°С†РёРµР№ CFB"""
        if not data:
            raise ValueError("РќРµР»СЊР·СЏ РґРµС€РёС„СЂРѕРІР°С‚СЊ РїСѓСЃС‚С‹Рµ РґР°РЅРЅС‹Рµ")

        if len(data) < self.block_size:
            raise ValueError(f"Р”Р°РЅРЅС‹Рµ СЃР»РёС€РєРѕРј РєРѕСЂРѕС‚РєРёРµ РґР»СЏ CFB СЂРµР¶РёРјР°. РњРёРЅРёРјСѓРј {self.block_size} Р±Р°Р№С‚ (IV)")

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

        plaintext = b""
        shift_register = iv

        # РћР±СЂР°Р±Р°С‚С‹РІР°РµРј ciphertext Р±Р»РѕРєР°РјРё
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 1. РЁРёС„СЂСѓРµРј СЃРѕРґРµСЂР¶РёРјРѕРµ shift register
            keystream = self.aes_primitive.encrypt(shift_register)

            # 2. XOR СЃ ciphertext РґР»СЏ РїРѕР»СѓС‡РµРЅРёСЏ plaintext
            decrypted_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            plaintext += decrypted_block

            # 3. РћР±РЅРѕРІР»СЏРµРј shift register
            # Р’ CFB РїСЂРё РґРµС€РёС„СЂРѕРІР°РЅРёРё shift register РѕР±РЅРѕРІР»СЏРµС‚СЃСЏ ciphertext Р±Р»РѕРєРѕРј
            if len(block) == self.block_size:
                shift_register = block
            else:
                shift_register = block + shift_register[len(block):]

        # CFB - РїРѕС‚РѕРєРѕРІС‹Р№ СЂРµР¶РёРј, padding РЅРµ РёСЃРїРѕР»СЊР·СѓРµС‚СЃСЏ
        # remove_padding РёРіРЅРѕСЂРёСЂСѓРµС‚СЃСЏ, РЅРѕ РїР°СЂР°РјРµС‚СЂ РѕСЃС‚Р°РІР»РµРЅ РґР»СЏ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё
        return plaintext

