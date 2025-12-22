"""
Р РµР°Р»РёР·Р°С†РёСЏ СЂРµР¶РёРјР° Cipher Block Chaining (CBC) РґР»СЏ AES
РЎ Р РЈР§РќРћР™ СЂРµР°Р»РёР·Р°С†РёРµР№ chaining РјРµС…Р°РЅРёР·РјР° (С‚СЂРµР±РѕРІР°РЅРёРµ CRY-2 Sprint 2)
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from src.csprng import generate_random_bytes


class CBCMode:
    """РљР»Р°СЃСЃ РґР»СЏ СЂР°Р±РѕС‚С‹ СЃ СЂРµР¶РёРјРѕРј CBC СЃ СЂСѓС‡РЅРѕР№ СЂРµР°Р»РёР·Р°С†РёРµР№ chaining"""

    def __init__(self, key, iv=None):
        if len(key) != 16:
            raise ValueError("РљР»СЋС‡ РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ 16 Р±Р°Р№С‚ РґР»СЏ AES-128")
        self.key = key
        self.block_size = AES.block_size

        # РЎРѕР·РґР°РµРј AES РїСЂРёРјРёС‚РёРІ РґР»СЏ С€РёС„СЂРѕРІР°РЅРёСЏ Р±Р»РѕРєРѕРІ
        self.aes_primitive = AES.new(self.key, AES.MODE_ECB)

        if iv:
            if len(iv) != 16:
                raise ValueError("IV РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ 16 Р±Р°Р№С‚")
            self.iv = iv
        else:
            # РСЃРїРѕР»СЊР·СѓРµРј CSPRNG РґР»СЏ РіРµРЅРµСЂР°С†РёРё IV
            self.iv = generate_random_bytes(16)

    def encrypt(self, plaintext, use_padding=True):
        """РЁРёС„СЂРѕРІР°РЅРёРµ СЃ СЂСѓС‡РЅРѕР№ СЂРµР°Р»РёР·Р°С†РёРµР№ CBC chaining"""
        if not plaintext:
            raise ValueError("РќРµР»СЊР·СЏ С€РёС„СЂРѕРІР°С‚СЊ РїСѓСЃС‚С‹Рµ РґР°РЅРЅС‹Рµ")

        # 1. Padding (С‚РѕР»СЊРєРѕ РµСЃР»Рё use_padding=True)
        if use_padding:
            padded_data = pad(plaintext, self.block_size)
        else:
            padded_data = plaintext
            # Р”Р»СЏ РїРѕС‚РѕРєРѕРІС‹С… СЂРµР¶РёРјРѕРІ Р±РµР· padding, РґР»РёРЅР° РґРѕР»Р¶РЅР° Р±С‹С‚СЊ РєСЂР°С‚РЅР° Р±Р»РѕРєСѓ
            if len(padded_data) % self.block_size != 0:
                raise ValueError(f"Р”Р»СЏ СЂРµР¶РёРјР° Р±РµР· padding РґР»РёРЅР° РґРѕР»Р¶РЅР° Р±С‹С‚СЊ РєСЂР°С‚РЅР° {self.block_size}")

        # 2. Р СѓС‡РЅР°СЏ СЂРµР°Р»РёР·Р°С†РёСЏ CBC
        ciphertext = b""
        previous_block = self.iv  # РќР°С‡РёРЅР°РµРј СЃ IV

        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]

            # 3. XOR СЃ РїСЂРµРґС‹РґСѓС‰РёРј Р±Р»РѕРєРѕРј (РёР»Рё IV РґР»СЏ РїРµСЂРІРѕРіРѕ)
            xored_block = bytes(a ^ b for a, b in zip(block, previous_block))

            # 4. РЁРёС„СЂРѕРІР°РЅРёРµ Р±Р»РѕРєР° AES РїСЂРёРјРёС‚РёРІРѕРј
            encrypted_block = self.aes_primitive.encrypt(xored_block)

            # 5. РЎРѕС…СЂР°РЅСЏРµРј РґР»СЏ СЃР»РµРґСѓСЋС‰РµРіРѕ Р±Р»РѕРєР°
            previous_block = encrypted_block
            ciphertext += encrypted_block

        return self.iv + ciphertext

    def decrypt(self, data, remove_padding=True):
        """Р”РµС€РёС„СЂРѕРІР°РЅРёРµ СЃ СЂСѓС‡РЅРѕР№ СЂРµР°Р»РёР·Р°С†РёРµР№ CBC chaining"""
        if not data:
            raise ValueError("РќРµР»СЊР·СЏ РґРµС€РёС„СЂРѕРІР°С‚СЊ РїСѓСЃС‚С‹Рµ РґР°РЅРЅС‹Рµ")

        # Р Р°Р·РґРµР»СЏРµРј IV Рё ciphertext
        if len(data) < self.block_size:
            raise ValueError(f"Р”Р°РЅРЅС‹Рµ СЃР»РёС€РєРѕРј РєРѕСЂРѕС‚РєРёРµ. РњРёРЅРёРјСѓРј {self.block_size} Р±Р°Р№С‚ (IV)")

        iv = data[:self.block_size]
        ciphertext = data[self.block_size:]

        # 1. Р СѓС‡РЅР°СЏ СЂРµР°Р»РёР·Р°С†РёСЏ CBC РґРµС€РёС„СЂРѕРІР°РЅРёСЏ
        plaintext = b""
        previous_block = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # 2. Р”РµС€РёС„СЂРѕРІР°РЅРёРµ Р±Р»РѕРєР° AES РїСЂРёРјРёС‚РёРІРѕРј
            decrypted_block = self.aes_primitive.decrypt(block)

            # 3. XOR СЃ РїСЂРµРґС‹РґСѓС‰РёРј Р±Р»РѕРєРѕРј (РёР»Рё IV РґР»СЏ РїРµСЂРІРѕРіРѕ)
            plain_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))

            # 4. РЎРѕС…СЂР°РЅСЏРµРј С‚РµРєСѓС‰РёР№ ciphertext Р±Р»РѕРє РґР»СЏ СЃР»РµРґСѓСЋС‰РµР№ РёС‚РµСЂР°С†РёРё
            previous_block = block
            plaintext += plain_block

        # 5. РЈРґР°Р»РµРЅРёРµ padding (РµСЃР»Рё С‚СЂРµР±СѓРµС‚СЃСЏ)
        if remove_padding and len(plaintext) > 0:
            try:
                # Р’РђР–РќРћ: OpenSSL РёСЃРїРѕР»СЊР·СѓРµС‚ PKCS#7 padding
                # РџСЂРѕРІРµСЂСЏРµРј РїРѕСЃР»РµРґРЅРёР№ Р±Р°Р№С‚
                last_byte = plaintext[-1]

                print(f"[DEBUG CBC] Р”Р»РёРЅР° plaintext РґРѕ СѓРґР°Р»РµРЅРёСЏ padding: {len(plaintext)}")
                print(f"[DEBUG CBC] РџРѕСЃР»РµРґРЅРёР№ Р±Р°Р№С‚: 0x{last_byte:02x} ({last_byte})")

                # PKCS#7 padding: РїРѕСЃР»РµРґРЅРёРµ N Р±Р°Р№С‚ РІСЃРµ СЂР°РІРЅС‹ N, РіРґРµ 1 <= N <= 16
                if 1 <= last_byte <= self.block_size:
                    # РџСЂРѕРІРµСЂСЏРµРј С‡С‚Рѕ РІСЃРµ РїРѕСЃР»РµРґРЅРёРµ last_byte Р±Р°Р№С‚ СЂР°РІРЅС‹ last_byte
                    expected_padding = bytes([last_byte]) * last_byte
                    actual_padding = plaintext[-last_byte:]

                    print(f"[DEBUG CBC] РћР¶РёРґР°РµРјС‹Р№ padding: {expected_padding.hex()}")
                    print(f"[DEBUG CBC] Р¤Р°РєС‚РёС‡РµСЃРєРёР№ padding: {actual_padding.hex()}")

                    if actual_padding == expected_padding:
                        # Р­С‚Рѕ valid PKCS#7 padding, СѓРґР°Р»СЏРµРј РµРіРѕ
                        result = plaintext[:-last_byte]
                        print(f"[DEBUG CBC] Padding СѓРґР°Р»РµРЅ, РЅРѕРІР°СЏ РґР»РёРЅР°: {len(result)}")
                        return result
                    else:
                        print(f"[DEBUG CBC] Padding РЅРµ СЃРѕРІРїР°РґР°РµС‚!")

                # Р•СЃР»Рё РЅРµ PKCS#7, РїСЂРѕР±СѓРµРј СЃС‚Р°РЅРґР°СЂС‚РЅС‹Р№ unpad РёР· pycryptodome
                from Crypto.Util.Padding import unpad
                try:
                    result = unpad(plaintext, self.block_size)
                    print(f"[DEBUG CBC] РСЃРїРѕР»СЊР·РѕРІР°РЅ unpad, РЅРѕРІР°СЏ РґР»РёРЅР°: {len(result)}")
                    return result
                except ValueError as e:
                    print(f"[DEBUG CBC] unpad РЅРµ СЃСЂР°Р±РѕС‚Р°Р»: {e}")
                    # Р•СЃР»Рё Рё СЌС‚Рѕ РЅРµ СЂР°Р±РѕС‚Р°РµС‚, РґР°РЅРЅС‹Рµ РјРѕРіСѓС‚ Р±С‹С‚СЊ СѓР¶Рµ Р±РµР· padding

            except Exception as e:
                # Р•СЃР»Рё РѕС€РёР±РєР°, Р»РѕРіРёСЂСѓРµРј Рё РІРѕР·РІСЂР°С‰Р°РµРј РєР°Рє РµСЃС‚СЊ
                print(f"[DEBUG CBC] РћС€РёР±РєР° РїСЂРё СѓРґР°Р»РµРЅРёРё padding: {e}")

        print(f"[DEBUG CBC] Padding РЅРµ СѓРґР°Р»РµРЅ, РІРѕР·РІСЂР°С‰Р°РµРј РєР°Рє РµСЃС‚СЊ: {len(plaintext)} Р±Р°Р№С‚")
        return plaintext

