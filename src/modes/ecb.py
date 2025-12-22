"""
Р РµР°Р»РёР·Р°С†РёСЏ СЂРµР¶РёРјР° Electronic Codebook (ECB) РґР»СЏ AES
РЎ Р РЈР§РќРћР™ РѕР±СЂР°Р±РѕС‚РєРѕР№ Р±Р»РѕРєРѕРІ (С‚СЂРµР±РѕРІР°РЅРёРµ CRY-3 Sprint 1)
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class ECBMode:
    """РљР»Р°СЃСЃ РґР»СЏ СЂР°Р±РѕС‚С‹ СЃ СЂРµР¶РёРјРѕРј ECB СЃ СЂСѓС‡РЅРѕР№ РѕР±СЂР°Р±РѕС‚РєРѕР№ Р±Р»РѕРєРѕРІ"""

    def __init__(self, key):
        """РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ ECB СЂРµР¶РёРјР°"""
        if len(key) != 16:
            raise ValueError(f"РќРµРєРѕСЂСЂРµРєС‚РЅР°СЏ РґР»РёРЅР° РєР»СЋС‡Р°: {len(key)} Р±Р°Р№С‚. Р”Р»СЏ AES-128 С‚СЂРµР±СѓРµС‚СЃСЏ 16 Р±Р°Р№С‚.")

        self.key = key
        self.block_size = AES.block_size  # 16 Р±Р°Р№С‚
        # РЎРѕР·РґР°РµРј AES РїСЂРёРјРёС‚РёРІ РґР»СЏ С€РёС„СЂРѕРІР°РЅРёСЏ/РґРµС€РёС„СЂРѕРІР°РЅРёСЏ РѕС‚РґРµР»СЊРЅС‹С… Р±Р»РѕРєРѕРІ
        self.aes_primitive = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, plaintext):
        """РЁРёС„СЂРѕРІР°РЅРёРµ РґР°РЅРЅС‹С… РІ СЂРµР¶РёРјРµ ECB СЃ Р РЈР§РќРћР™ РѕР±СЂР°Р±РѕС‚РєРѕР№ Р±Р»РѕРєРѕРІ"""
        if not plaintext:
            raise ValueError("РќРµР»СЊР·СЏ С€РёС„СЂРѕРІР°С‚СЊ РїСѓСЃС‚С‹Рµ РґР°РЅРЅС‹Рµ")

        # 1. Р”РѕР±Р°РІР»СЏРµРј padding РїРѕ СЃС‚Р°РЅРґР°СЂС‚Сѓ PKCS#7
        padded_data = pad(plaintext, self.block_size)

        # 2. Р РЈР§РќРћР• СЂР°Р·РґРµР»РµРЅРёРµ РЅР° Р±Р»РѕРєРё Рё РѕР±СЂР°Р±РѕС‚РєР° РєР°Р¶РґРѕРіРѕ Р±Р»РѕРєР°
        ciphertext = b""

        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]

            # 3. Р’С‹Р·РѕРІ AES РїСЂРёРјРёС‚РёРІР° РґР»СЏ РєР°Р¶РґРѕРіРѕ Р±Р»РѕРєР° РѕС‚РґРµР»СЊРЅРѕ
            encrypted_block = self.aes_primitive.encrypt(block)

            # 4. РЎР±РѕСЂРєР° СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ
            ciphertext += encrypted_block

        return ciphertext

    def decrypt(self, ciphertext, remove_padding=True):  # Р”РѕР±Р°РІР»СЏРµРј remove_padding РґР»СЏ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё
        """Р”РµС€РёС„СЂРѕРІР°РЅРёРµ РґР°РЅРЅС‹С… РІ СЂРµР¶РёРјРµ ECB СЃ Р РЈР§РќРћР™ РѕР±СЂР°Р±РѕС‚РєРѕР№ Р±Р»РѕРєРѕРІ"""
        if not ciphertext:
            raise ValueError("РќРµР»СЊР·СЏ РґРµС€РёС„СЂРѕРІР°С‚СЊ РїСѓСЃС‚С‹Рµ РґР°РЅРЅС‹Рµ")

        # РџСЂРѕРІРµСЂСЏРµРј, С‡С‚Рѕ РґР»РёРЅР° РєСЂР°С‚РЅР° СЂР°Р·РјРµСЂСѓ Р±Р»РѕРєР°
        if len(ciphertext) % self.block_size != 0:
            raise ValueError(f"Р”Р»РёРЅР° Р·Р°С€РёС„СЂРѕРІР°РЅРЅС‹С… РґР°РЅРЅС‹С… ({len(ciphertext)} Р±Р°Р№С‚) РґРѕР»Р¶РЅР° Р±С‹С‚СЊ РєСЂР°С‚РЅР° {self.block_size} Р±Р°Р№С‚Р°Рј")

        # 1. Р РЈР§РќРћР• СЂР°Р·РґРµР»РµРЅРёРµ РЅР° Р±Р»РѕРєРё
        padded_plaintext = b""

        # 2. РћР±СЂР°Р±РѕС‚РєР° РєР°Р¶РґРѕРіРѕ Р±Р»РѕРєР° РїРѕ РѕС‚РґРµР»СЊРЅРѕСЃС‚Рё
        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 3. Р’С‹Р·РѕРІ AES РїСЂРёРјРёС‚РёРІР° РґР»СЏ РєР°Р¶РґРѕРіРѕ Р±Р»РѕРєР°
            decrypted_block = self.aes_primitive.decrypt(block)

            # 4. РЎР±РѕСЂРєР° СЂРµР·СѓР»СЊС‚Р°С‚РѕРІ
            padded_plaintext += decrypted_block

        # 5. РЈРґР°Р»РµРЅРёРµ padding (РµСЃР»Рё С‚СЂРµР±СѓРµС‚СЃСЏ)
        if remove_padding:
            try:
                plaintext = unpad(padded_plaintext, self.block_size)
            except ValueError:
                # Р•СЃР»Рё padding РЅРµРІРµСЂРЅС‹Р№, РІРѕР·РІСЂР°С‰Р°РµРј РєР°Рє РµСЃС‚СЊ
                plaintext = padded_plaintext
        else:
            plaintext = padded_plaintext

        return plaintext

