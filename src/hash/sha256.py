"""
Р РµР°Р»РёР·Р°С†РёСЏ SHA-256 СЃ РЅСѓР»СЏ
Sprint 4: РЎР»РµРґРѕРІР°РЅРёРµ NIST FIPS 180-4
РџРѕР»РЅРѕСЃС‚СЊСЋ СЂСѓС‡РЅР°СЏ СЂРµР°Р»РёР·Р°С†РёСЏ Р±РµР· РёСЃРїРѕР»СЊР·РѕРІР°РЅРёСЏ СЃС‚РѕСЂРѕРЅРЅРёС… Р±РёР±Р»РёРѕС‚РµРє
"""

import struct


class SHA256:
    """Р РµР°Р»РёР·Р°С†РёСЏ SHA-256 С…РµС€-С„СѓРЅРєС†РёРё СЃ РЅСѓР»СЏ"""

    # РќР°С‡Р°Р»СЊРЅС‹Рµ Р·РЅР°С‡РµРЅРёСЏ (РїРµСЂРІС‹Рµ 32 Р±РёС‚Р° РґСЂРѕР±РЅС‹С… С‡Р°СЃС‚РµР№ РєРІР°РґСЂР°С‚РЅС‹С… РєРѕСЂРЅРµР№ РїРµСЂРІС‹С… 8 РїСЂРѕСЃС‚С‹С… С‡РёСЃРµР»)
    INITIAL_HASH = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # РљРѕРЅСЃС‚Р°РЅС‚С‹ (РїРµСЂРІС‹Рµ 32 Р±РёС‚Р° РґСЂРѕР±РЅС‹С… С‡Р°СЃС‚РµР№ РєСѓР±РёС‡РµСЃРєРёС… РєРѕСЂРЅРµР№ РїРµСЂРІС‹С… 64 РїСЂРѕСЃС‚С‹С… С‡РёСЃРµР»)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    def __init__(self):
        """РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ SHA-256"""
        self.hash_values = self.INITIAL_HASH[:]  # РўРµРєСѓС‰РёРµ Р·РЅР°С‡РµРЅРёСЏ С…РµС€Р° (H0-H7)
        self.message_length = 0  # Р”Р»РёРЅР° СЃРѕРѕР±С‰РµРЅРёСЏ РІ Р±РёС‚Р°С…
        self.buffer = bytearray()  # Р‘СѓС„РµСЂ РґР»СЏ РЅРµРїРѕР»РЅС‹С… Р±Р»РѕРєРѕРІ
        self.block_size = 64  # Р Р°Р·РјРµСЂ Р±Р»РѕРєР° РІ Р±Р°Р№С‚Р°С… (512 Р±РёС‚)

    def reset(self):
        """РЎР±СЂРѕСЃ СЃРѕСЃС‚РѕСЏРЅРёСЏ РґР»СЏ РїРѕРІС‚РѕСЂРЅРѕРіРѕ РёСЃРїРѕР»СЊР·РѕРІР°РЅРёСЏ"""
        self.hash_values = self.INITIAL_HASH[:]
        self.message_length = 0
        self.buffer = bytearray()

    @staticmethod
    def _right_rotate(x, n):
        """Р¦РёРєР»РёС‡РµСЃРєРёР№ СЃРґРІРёРі РІРїСЂР°РІРѕ 32-Р±РёС‚РЅРѕРіРѕ С‡РёСЃР»Р°"""
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _ch(x, y, z):
        """Р¤СѓРЅРєС†РёСЏ РІС‹Р±РѕСЂР° (Choice)"""
        return (x & y) ^ (~x & z)

    @staticmethod
    def _maj(x, y, z):
        """Р¤СѓРЅРєС†РёСЏ Р±РѕР»СЊС€РёРЅСЃС‚РІР° (Majority)"""
        return (x & y) ^ (x & z) ^ (y & z)

    @staticmethod
    def _sigma0(x):
        """Р¤СѓРЅРєС†РёСЏ Пѓ0"""
        return (SHA256._right_rotate(x, 7) ^
                SHA256._right_rotate(x, 18) ^
                (x >> 3))

    @staticmethod
    def _sigma1(x):
        """Р¤СѓРЅРєС†РёСЏ Пѓ1"""
        return (SHA256._right_rotate(x, 17) ^
                SHA256._right_rotate(x, 19) ^
                (x >> 10))

    @staticmethod
    def _capital_sigma0(x):
        """Р¤СѓРЅРєС†РёСЏ ОЈ0"""
        return (SHA256._right_rotate(x, 2) ^
                SHA256._right_rotate(x, 13) ^
                SHA256._right_rotate(x, 22))

    @staticmethod
    def _capital_sigma1(x):
        """Р¤СѓРЅРєС†РёСЏ ОЈ1"""
        return (SHA256._right_rotate(x, 6) ^
                SHA256._right_rotate(x, 11) ^
                SHA256._right_rotate(x, 25))

    def _process_block(self, block):
        """РћР±СЂР°Р±РѕС‚РєР° РѕРґРЅРѕРіРѕ 512-Р±РёС‚РЅРѕРіРѕ Р±Р»РѕРєР°"""
        if len(block) != self.block_size:
            raise ValueError(f"Р‘Р»РѕРє РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ {self.block_size} Р±Р°Р№С‚, РїРѕР»СѓС‡РµРЅРѕ {len(block)}")

        # 1. РџРѕРґРіРѕС‚РѕРІРєР° СЂР°СЃРїРёСЃР°РЅРёСЏ СЃРѕРѕР±С‰РµРЅРёР№ (message schedule)
        w = [0] * 64

        # РџРµСЂРІС‹Рµ 16 СЃР»РѕРІ РёР· Р±Р»РѕРєР° (big-endian)
        for i in range(16):
            w[i] = struct.unpack('>I', block[i * 4:(i + 1) * 4])[0]

        # РћСЃС‚Р°Р»СЊРЅС‹Рµ 48 СЃР»РѕРІ
        for i in range(16, 64):
            s0 = self._sigma0(w[i - 15])
            s1 = self._sigma1(w[i - 2])
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        # 2. РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ СЂР°Р±РѕС‡РёС… РїРµСЂРµРјРµРЅРЅС‹С…
        a, b, c, d, e, f, g, h = self.hash_values

        # 3. Р“Р»Р°РІРЅС‹Р№ С†РёРєР» СЃР¶Р°С‚РёСЏ (64 СЂР°СѓРЅРґР°)
        for i in range(64):
            t1 = (h + self._capital_sigma1(e) + self._ch(e, f, g) +
                  self.K[i] + w[i]) & 0xFFFFFFFF
            t2 = (self._capital_sigma0(a) + self._maj(a, b, c)) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        # 4. Р”РѕР±Р°РІР»РµРЅРёРµ СЃР¶Р°С‚РѕРіРѕ Р±Р»РѕРєР° Рє С‚РµРєСѓС‰РµРјСѓ С…РµС€Сѓ
        self.hash_values[0] = (self.hash_values[0] + a) & 0xFFFFFFFF
        self.hash_values[1] = (self.hash_values[1] + b) & 0xFFFFFFFF
        self.hash_values[2] = (self.hash_values[2] + c) & 0xFFFFFFFF
        self.hash_values[3] = (self.hash_values[3] + d) & 0xFFFFFFFF
        self.hash_values[4] = (self.hash_values[4] + e) & 0xFFFFFFFF
        self.hash_values[5] = (self.hash_values[5] + f) & 0xFFFFFFFF
        self.hash_values[6] = (self.hash_values[6] + g) & 0xFFFFFFFF
        self.hash_values[7] = (self.hash_values[7] + h) & 0xFFFFFFFF

    def _pad_message(self):
        """Р”РѕР±Р°РІР»РµРЅРёРµ padding РїРѕ СЃС‚Р°РЅРґР°СЂС‚Сѓ SHA-256"""
        # Р”Р»РёРЅР° СЃРѕРѕР±С‰РµРЅРёСЏ РІ Р±РёС‚Р°С…
        bit_length = self.message_length * 8

        # Р”РѕР±Р°РІР»СЏРµРј Р±РёС‚ '1' (0x80)
        padding = bytearray([0x80])

        # Р”РѕР±Р°РІР»СЏРµРј РЅСѓР»Рё РґРѕ С‚РµС… РїРѕСЂ, РїРѕРєР° РґР»РёРЅР° РЅРµ СЃС‚Р°РЅРµС‚ 448 Р±РёС‚ (56 Р±Р°Р№С‚) РїРѕ РјРѕРґСѓР»СЋ 512
        # РўРµРєСѓС‰Р°СЏ РґР»РёРЅР° РІ Р±Р°Р№С‚Р°С… СЃ СѓС‡РµС‚РѕРј РґРѕР±Р°РІР»РµРЅРЅРѕРіРѕ 0x80
        current_length = len(self.buffer) + len(padding)

        # РќСѓР¶РЅРѕ РґРѕР±Р°РІРёС‚СЊ k РЅСѓР»РµР№, РіРґРµ (l + 1 + k) в‰Ў 448 mod 512
        # l - РёСЃС…РѕРґРЅР°СЏ РґР»РёРЅР°, 1 - Р±Р°Р№С‚ 0x80
        # РџСЂРµРѕР±СЂР°Р·СѓРµРј: k = (448 - (l + 1)) mod 512
        # РќРѕ С‚Р°Рє РєР°Рє РјС‹ СЂР°Р±РѕС‚Р°РµРј СЃ Р±Р°Р№С‚Р°РјРё: k_zero_bytes = (56 - ((l + 1) % 64)) % 64

        k_zero_bytes = (56 - (current_length % 64)) % 64
        if k_zero_bytes < 0:
            k_zero_bytes += 64

        padding.extend([0] * k_zero_bytes)

        # Р”РѕР±Р°РІР»СЏРµРј РґР»РёРЅСѓ СЃРѕРѕР±С‰РµРЅРёСЏ РІ Р±РёС‚Р°С… РєР°Рє 64-Р±РёС‚РЅРѕРµ big-endian С‡РёСЃР»Рѕ
        padding.extend(struct.pack('>Q', bit_length))

        return padding

    def update(self, data):
        """
        Р”РѕР±Р°РІР»РµРЅРёРµ РґР°РЅРЅС‹С… РґР»СЏ С…РµС€РёСЂРѕРІР°РЅРёСЏ
        РџРѕРґРґРµСЂР¶РёРІР°РµС‚ РёРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕРµ С…РµС€РёСЂРѕРІР°РЅРёРµ
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Р”РѕР±Р°РІР»СЏРµРј РґР°РЅРЅС‹Рµ РІ Р±СѓС„РµСЂ
        self.buffer.extend(data)
        self.message_length += len(data)

        # РћР±СЂР°Р±Р°С‚С‹РІР°РµРј РїРѕР»РЅС‹Рµ Р±Р»РѕРєРё
        while len(self.buffer) >= self.block_size:
            block = bytes(self.buffer[:self.block_size])
            self._process_block(block)
            del self.buffer[:self.block_size]

    def digest(self):
        """Р’РѕР·РІСЂР°С‰Р°РµС‚ С„РёРЅР°Р»СЊРЅС‹Р№ С…РµС€ РІ Р±РёРЅР°СЂРЅРѕРј С„РѕСЂРјР°С‚Рµ"""
        # РЎРѕС…СЂР°РЅСЏРµРј С‚РµРєСѓС‰РµРµ СЃРѕСЃС‚РѕСЏРЅРёРµ
        temp_hash = self.hash_values[:]
        temp_buffer = self.buffer[:]
        temp_length = self.message_length

        # Р”РѕР±Р°РІР»СЏРµРј padding
        padding = self._pad_message()
        self.update(padding)  # РСЃРїРѕР»СЊР·СѓРµРј update РґР»СЏ РїСЂР°РІРёР»СЊРЅРѕР№ РѕР±СЂР°Р±РѕС‚РєРё padding

        # Р¤РѕСЂРјРёСЂСѓРµРј СЂРµР·СѓР»СЊС‚Р°С‚
        result = bytearray()
        for h_val in self.hash_values:
            result.extend(struct.pack('>I', h_val))

        # Р’РѕСЃСЃС‚Р°РЅР°РІР»РёРІР°РµРј СЃРѕСЃС‚РѕСЏРЅРёРµ (РЅР° СЃР»СѓС‡Р°Р№ РµСЃР»Рё РїСЂРѕРґРѕР»Р¶РёРј update)
        self.hash_values = temp_hash
        self.buffer = temp_buffer
        self.message_length = temp_length

        return bytes(result)

    def hexdigest(self):
        """Р’РѕР·РІСЂР°С‰Р°РµС‚ С„РёРЅР°Р»СЊРЅС‹Р№ С…РµС€ РІ hex С„РѕСЂРјР°С‚Рµ (РЅРёР¶РЅРёР№ СЂРµРіРёСЃС‚СЂ)"""
        return self.digest().hex().lower()

    @staticmethod
    def hash(data):
        """РЈРґРѕР±РЅС‹Р№ РјРµС‚РѕРґ РґР»СЏ РѕРґРЅРѕРєСЂР°С‚РЅРѕРіРѕ С…РµС€РёСЂРѕРІР°РЅРёСЏ"""
        sha = SHA256()
        sha.update(data)
        return sha.hexdigest()

    def hash_file(self, filepath, chunk_size=8192):
        """
        РҐРµС€РёСЂРѕРІР°РЅРёРµ С„Р°Р№Р»Р° С‡Р°РЅРєР°РјРё
        chunk_size: СЂР°Р·РјРµСЂ С‡Р°РЅРєР° РІ Р±Р°Р№С‚Р°С…
        """
        import os

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Р¤Р°Р№Р» РЅРµ РЅР°Р№РґРµРЅ: {filepath}")

        # РЎР±СЂР°СЃС‹РІР°РµРј СЃРѕСЃС‚РѕСЏРЅРёРµ РґР»СЏ РЅРѕРІРѕРіРѕ С„Р°Р№Р»Р°
        self.__init__()

        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                self.update(chunk)

        return self.hexdigest()


# РўРµСЃС‚РёСЂРѕРІР°РЅРёРµ РїСЂРё РїСЂСЏРјРѕРј Р·Р°РїСѓСЃРєРµ
if __name__ == "__main__":
    print("=== РўР•РЎРў SHA-256 ===")

    # РўРµСЃС‚РѕРІС‹Рµ РІРµРєС‚РѕСЂС‹ РёР· NIST
    test_cases = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ]

    all_pass = True
    for i, (input_str, expected) in enumerate(test_cases):
        result = SHA256.hash(input_str)
        if result == expected:
            print(f"вњ… РўРµСЃС‚ {i + 1} РїСЂРѕР№РґРµРЅ")
        else:
            print(f"вќЊ РўРµСЃС‚ {i + 1} РЅРµ РїСЂРѕР№РґРµРЅ")
            print(f"   Р’С…РѕРґ: '{input_str[:30]}{'...' if len(input_str) > 30 else ''}'")
            print(f"   РћР¶РёРґР°Р»РѕСЃСЊ: {expected}")
            print(f"   РџРѕР»СѓС‡РµРЅРѕ:  {result}")
            all_pass = False

    if all_pass:
        print("\nвњ… Р’СЃРµ С‚РµСЃС‚С‹ SHA-256 РїСЂРѕР№РґРµРЅС‹!")
    else:
        print("\nвќЊ РќРµРєРѕС‚РѕСЂС‹Рµ С‚РµСЃС‚С‹ РЅРµ РїСЂРѕР№РґРµРЅС‹")

