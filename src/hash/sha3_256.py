"""
Р РµР°Р»РёР·Р°С†РёСЏ SHA3-256 СЃ РЅСѓР»СЏ
Sprint 4: РЎР»РµРґРѕРІР°РЅРёРµ NIST FIPS 202 (Keccak sponge construction)
"""

import struct


class SHA3_256:
    """Р РµР°Р»РёР·Р°С†РёСЏ SHA3-256 С…РµС€-С„СѓРЅРєС†РёРё СЃ РЅСѓР»СЏ"""

    # РџР°СЂР°РјРµС‚СЂС‹ РґР»СЏ SHA3-256
    RATE = 1088  # РЎРєРѕСЂРѕСЃС‚СЊ (r) РІ Р±РёС‚Р°С… = 136 Р±Р°Р№С‚
    CAPACITY = 512  # Р•РјРєРѕСЃС‚СЊ (c) РІ Р±РёС‚Р°С…
    OUTPUT_SIZE = 256  # Р Р°Р·РјРµСЂ РІС‹С…РѕРґР° РІ Р±РёС‚Р°С… = 32 Р±Р°Р№С‚Р°
    BLOCK_SIZE = 136  # Р Р°Р·РјРµСЂ Р±Р»РѕРєР° РІ Р±Р°Р№С‚Р°С… (RATE/8)

    # РљРѕРЅСЃС‚Р°РЅС‚С‹ РґР»СЏ Keccak-f[1600]
    ROUND_CONSTANTS = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ]

    ROTATION_OFFSETS = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ]

    def __init__(self):
        """РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ SHA3-256"""
        # РЎРѕСЃС‚РѕСЏРЅРёРµ Keccak (5x5 РјР°С‚СЂРёС†Р° 64-Р±РёС‚РЅС‹С… СЃР»РѕРІ)
        self.state = [[0] * 5 for _ in range(5)]
        self.buffer = bytearray()
        self._is_finalized = False

    def reset(self):
        """РЎР±СЂРѕСЃ СЃРѕСЃС‚РѕСЏРЅРёСЏ РґР»СЏ РїРѕРІС‚РѕСЂРЅРѕРіРѕ РёСЃРїРѕР»СЊР·РѕРІР°РЅРёСЏ"""
        self.state = [[0] * 5 for _ in range(5)]
        self.buffer = bytearray()
        self._is_finalized = False
        if hasattr(self, '_final_hash'):
            delattr(self, '_final_hash')

    @staticmethod
    def _rotate_left_64(x, n):
        """Р¦РёРєР»РёС‡РµСЃРєРёР№ СЃРґРІРёРі 64-Р±РёС‚РЅРѕРіРѕ С‡РёСЃР»Р° РІР»РµРІРѕ"""
        n = n % 64
        return ((x << n) & ((1 << 64) - 1)) | (x >> (64 - n))

    def _theta(self):
        """Р¤СѓРЅРєС†РёСЏ Оё (theta)"""
        c = [0] * 5
        d = [0] * 5

        # Р’С‹С‡РёСЃР»СЏРµРј СЃС‚РѕР»Р±С†РѕРІС‹Рµ СЃСѓРјРјС‹
        for x in range(5):
            c[x] = (self.state[x][0] ^ self.state[x][1] ^
                    self.state[x][2] ^ self.state[x][3] ^
                    self.state[x][4])

        # Р’С‹С‡РёСЃР»СЏРµРј d
        for x in range(5):
            d[x] = c[(x - 1) % 5] ^ self._rotate_left_64(c[(x + 1) % 5], 1)

        # РџСЂРёРјРµРЅСЏРµРј Рє СЃРѕСЃС‚РѕСЏРЅРёСЋ
        for x in range(5):
            for y in range(5):
                self.state[x][y] ^= d[x]

    def _rho_pi(self):
        """Р¤СѓРЅРєС†РёРё ПЃ (rho) Рё ПЂ (pi)"""
        new_state = [[0] * 5 for _ in range(5)]

        for x in range(5):
            for y in range(5):
                # РџСЂРёРјРµРЅСЏРµРј ПЂ РїРµСЂРµСЃС‚Р°РЅРѕРІРєСѓ
                new_x = y
                new_y = (2 * x + 3 * y) % 5

                # РџСЂРёРјРµРЅСЏРµРј ПЃ СЃРґРІРёРі
                rotated = self._rotate_left_64(
                    self.state[x][y],
                    self.ROTATION_OFFSETS[x][y]
                )
                new_state[new_x][new_y] = rotated

        self.state = new_state

    def _chi(self):
        """Р¤СѓРЅРєС†РёСЏ П‡ (chi)"""
        new_state = [[0] * 5 for _ in range(5)]

        for x in range(5):
            for y in range(5):
                new_state[x][y] = (self.state[x][y] ^
                                   ((~self.state[(x + 1) % 5][y]) &
                                    self.state[(x + 2) % 5][y]))

        self.state = new_state

    def _iota(self, round_idx):
        """Р¤СѓРЅРєС†РёСЏ О№ (iota) - РґРѕР±Р°РІР»РµРЅРёРµ round constant"""
        self.state[0][0] ^= self.ROUND_CONSTANTS[round_idx]

    def _keccak_f(self):
        """Р¤СѓРЅРєС†РёСЏ РїРµСЂРµСЃС‚Р°РЅРѕРІРєРё Keccak-f[1600] (24 СЂР°СѓРЅРґР°)"""
        for round_idx in range(24):
            self._theta()
            self._rho_pi()
            self._chi()
            self._iota(round_idx)

    def _absorb_block(self, block):
        """РџРѕРіР»РѕС‰РµРЅРёРµ Р±Р»РѕРєР° РІ СЃРѕСЃС‚РѕСЏРЅРёРµ"""
        # Р‘Р»РѕРє РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ 136 Р±Р°Р№С‚ РґР»СЏ SHA3-256
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(f"Р‘Р»РѕРє РґРѕР»Р¶РµРЅ Р±С‹С‚СЊ {self.BLOCK_SIZE} Р±Р°Р№С‚, РїРѕР»СѓС‡РµРЅРѕ {len(block)}")

        # РџСЂРµРѕР±СЂР°Р·СѓРµРј Р±Р»РѕРє РІ 64-Р±РёС‚РЅС‹Рµ СЃР»РѕРІР° Рё XOR СЃ СЃРѕСЃС‚РѕСЏРЅРёРµРј
        for i in range(self.BLOCK_SIZE // 8):  # 136/8 = 17 СЃР»РѕРІ
            # Р’С‹С‡РёСЃР»СЏРµРј РїРѕР·РёС†РёСЋ РІ СЃРѕСЃС‚РѕСЏРЅРёРё (5x5)
            pos = i
            x = pos % 5
            y = pos // 5

            # РР·РІР»РµРєР°РµРј СЃР»РѕРІРѕ РёР· Р±Р»РѕРєР° (little-endian)
            word_bytes = block[i * 8:(i + 1) * 8]
            word = struct.unpack('<Q', word_bytes)[0]

            # XOR СЃ СЃРѕСЃС‚РѕСЏРЅРёРµРј
            self.state[x][y] ^= word

    def _pad(self, length):
        """Р”РѕР±Р°РІР»РµРЅРёРµ padding РґР»СЏ SHA-3"""
        # SHA-3 РёСЃРїРѕР»СЊР·СѓРµС‚ multi-rate padding
        # Р¤РѕСЂРјСѓР»Р°: M || 0x06 || 0x00... || 0x80

        block_size = self.BLOCK_SIZE
        padding_length = block_size - (length % block_size)

        if padding_length == 1:
            # РЎРїРµС†РёР°Р»СЊРЅС‹Р№ СЃР»СѓС‡Р°Р№: РЅСѓР¶РЅРѕ РґРѕР±Р°РІРёС‚СЊ РЅРѕРІС‹Р№ Р±Р»РѕРє
            padding = bytearray([0x86])  # 0x06 | 0x80
        elif padding_length == 2:
            padding = bytearray([0x06, 0x80])
        else:
            padding = bytearray([0x06])
            padding.extend([0] * (padding_length - 2))
            padding.append(0x80)

        return padding

    def update(self, data):
        """Р”РѕР±Р°РІР»РµРЅРёРµ РґР°РЅРЅС‹С… РґР»СЏ С…РµС€РёСЂРѕРІР°РЅРёСЏ"""
        if self._is_finalized:
            raise RuntimeError("РҐРµС€ СѓР¶Рµ С„РёРЅР°Р»РёР·РёСЂРѕРІР°РЅ")

        if isinstance(data, str):
            data = data.encode('utf-8')

        self.buffer.extend(data)

        # РџРѕРіР»РѕС‰Р°РµРј РїРѕР»РЅС‹Рµ Р±Р»РѕРєРё
        while len(self.buffer) >= self.BLOCK_SIZE:
            block = bytes(self.buffer[:self.BLOCK_SIZE])
            self._absorb_block(block)
            self._keccak_f()
            del self.buffer[:self.BLOCK_SIZE]

    def digest(self):
        """Р’РѕР·РІСЂР°С‰Р°РµС‚ С„РёРЅР°Р»СЊРЅС‹Р№ С…РµС€ РІ Р±РёРЅР°СЂРЅРѕРј С„РѕСЂРјР°С‚Рµ"""
        if self._is_finalized:
            # Р’РѕР·РІСЂР°С‰Р°РµРј РєСЌС€РёСЂРѕРІР°РЅРЅС‹Р№ СЂРµР·СѓР»СЊС‚Р°С‚
            return self._final_hash

        # Р”РѕР±Р°РІР»СЏРµРј padding
        padding = self._pad(len(self.buffer))
        self.buffer.extend(padding)

        # РџРѕРіР»РѕС‰Р°РµРј РїРѕСЃР»РµРґРЅРёР№ Р±Р»РѕРє
        if len(self.buffer) != self.BLOCK_SIZE:
            raise ValueError(f"РџРѕСЃР»Рµ padding РґР»РёРЅР° РґРѕР»Р¶РЅР° Р±С‹С‚СЊ {self.BLOCK_SIZE}, РїРѕР»СѓС‡РµРЅРѕ {len(self.buffer)}")

        block = bytes(self.buffer[:self.BLOCK_SIZE])
        self._absorb_block(block)
        self._keccak_f()

        # Р’С‹Р¶РёРјР°РµРј СЂРµР·СѓР»СЊС‚Р°С‚ (squeezing phase)
        result = bytearray()
        output_bytes = self.OUTPUT_SIZE // 8  # 32 Р±Р°Р№С‚Р°
        bytes_extracted = 0

        while bytes_extracted < output_bytes:
            # РџСЂРµРѕР±СЂР°Р·СѓРµРј С‡Р°СЃС‚СЊ СЃРѕСЃС‚РѕСЏРЅРёСЏ РІ Р±Р°Р№С‚С‹
            for y in range(5):
                for x in range(5):
                    if bytes_extracted >= output_bytes:
                        break

                    # РљРѕРЅРІРµСЂС‚РёСЂСѓРµРј СЃР»РѕРІРѕ РІ Р±Р°Р№С‚С‹ (little-endian)
                    word_bytes = struct.pack('<Q', self.state[x][y])

                    # Р”РѕР±Р°РІР»СЏРµРј СЃРєРѕР»СЊРєРѕ РЅСѓР¶РЅРѕ Р±Р°Р№С‚
                    bytes_needed = min(8, output_bytes - bytes_extracted)
                    result.extend(word_bytes[:bytes_needed])
                    bytes_extracted += bytes_needed

            if bytes_extracted < output_bytes:
                self._keccak_f()

        # РљСЌС€РёСЂСѓРµРј СЂРµР·СѓР»СЊС‚Р°С‚
        self._final_hash = bytes(result[:output_bytes])
        self._is_finalized = True

        return self._final_hash

    def hexdigest(self):
        """Р’РѕР·РІСЂР°С‰Р°РµС‚ С„РёРЅР°Р»СЊРЅС‹Р№ С…РµС€ РІ hex С„РѕСЂРјР°С‚Рµ (РЅРёР¶РЅРёР№ СЂРµРіРёСЃС‚СЂ)"""
        return self.digest().hex().lower()

    @staticmethod
    def hash(data):
        """РЈРґРѕР±РЅС‹Р№ РјРµС‚РѕРґ РґР»СЏ РѕРґРЅРѕРєСЂР°С‚РЅРѕРіРѕ С…РµС€РёСЂРѕРІР°РЅРёСЏ"""
        sha3 = SHA3_256()
        sha3.update(data)
        return sha3.hexdigest()

    def hash_file(self, filepath, chunk_size=8192):
        """РҐРµС€РёСЂРѕРІР°РЅРёРµ С„Р°Р№Р»Р° С‡Р°РЅРєР°РјРё"""
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


# Р‘С‹СЃС‚СЂС‹Р№ С‚РµСЃС‚ С„СѓРЅРєС†РёРё
if __name__ == "__main__":
    print("=== РўР•РЎРў SHA3-256 ===")

    # РўРµСЃС‚ 1: РџСѓСЃС‚Р°СЏ СЃС‚СЂРѕРєР°
    sha3 = SHA3_256()
    result = sha3.hash("")
    expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    print(f"РџСѓСЃС‚Р°СЏ СЃС‚СЂРѕРєР°: {result == expected} {result}")

    # РўРµСЃС‚ 2: "abc"
    sha3 = SHA3_256()
    result = sha3.hash("abc")
    expected = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    print(f"'abc': {result == expected} {result}")

