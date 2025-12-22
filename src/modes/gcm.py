import os
import struct
from src.cipher import AES

class AuthenticationError(Exception):
    """РСЃРєР»СЋС‡РµРЅРёРµ РґР»СЏ РѕС€РёР±РѕРє Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё GCM"""
    pass

class GCM:
    def __init__(self, key, nonce=None):
        """
        РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ GCM СЃ РєР»СЋС‡РѕРј Рё nonce
        
        Args:
            key (bytes): РљР»СЋС‡ AES (16, 24 РёР»Рё 32 Р±Р°Р№С‚Р°)
            nonce (bytes): Nonce (СЂРµРєРѕРјРµРЅРґСѓРµС‚СЃСЏ 12 Р±Р°Р№С‚)
        """
        self.aes = AES(key)
        self.key = key
        
        # РЎС‚Р°РЅРґР°СЂС‚РЅС‹Р№ СЂР°Р·РјРµСЂ nonce РґР»СЏ GCM - 12 Р±Р°Р№С‚
        if nonce is None:
            self.nonce = os.urandom(12)
        else:
            self.nonce = nonce
        
        # РџСЂРµРґРІС‹С‡РёСЃР»РµРЅРЅР°СЏ С‚Р°Р±Р»РёС†Р° РґР»СЏ СѓРјРЅРѕР¶РµРЅРёСЏ РІ GF(2^128)
        self._precompute_table()
        
        # РљРѕРЅСЃС‚Р°РЅС‚С‹
        self.block_size = 16  # Р Р°Р·РјРµСЂ Р±Р»РѕРєР° AES
        
    def _precompute_table(self):
        """РџСЂРµРґРІС‹С‡РёСЃР»РµРЅРёРµ С‚Р°Р±Р»РёС†С‹ РґР»СЏ СѓРјРЅРѕР¶РµРЅРёСЏ РІ GF(2^128)"""
        # РСЃРїРѕР»СЊР·СѓРµРј РїРѕР»РёРЅРѕРј: x^128 + x^7 + x^2 + x + 1
        self.r = 0xE1000000000000000000000000000000
        self.table = [0] * 16
        
        # H = E_K(0^128)
        h = self._bytes_to_int(self.aes.encrypt_block(bytes(16)))
        
        # РџСЂРµРґРІС‹С‡РёСЃР»РµРЅРёРµ С‚Р°Р±Р»РёС†С‹
        self.table[0] = 0
        self.table[1] = h
        
        for i in range(2, 16, 2):
            # РЈРјРЅРѕР¶РµРЅРёРµ РЅР° 2
            self.table[i] = self._mul2(self.table[i // 2])
            self.table[i + 1] = self._int_xor(self.table[i], self.table[1])
    
    def _bytes_to_int(self, data):
        """РљРѕРЅРІРµСЂС‚Р°С†РёСЏ Р±Р°Р№С‚РѕРІ РІ С†РµР»РѕРµ С‡РёСЃР»Рѕ (big-endian)"""
        return int.from_bytes(data, byteorder='big')
    
    def _int_to_bytes(self, num, length=16):
        """РљРѕРЅРІРµСЂС‚Р°С†РёСЏ С†РµР»РѕРіРѕ С‡РёСЃР»Р° РІ Р±Р°Р№С‚С‹ (big-endian)"""
        return num.to_bytes(length, byteorder='big')
    
    def _int_xor(self, a, b):
        """XOR РґРІСѓС… С†РµР»С‹С… С‡РёСЃРµР»"""
        return a ^ b
    
    def _mul2(self, x):
        """РЈРјРЅРѕР¶РµРЅРёРµ РЅР° 2 РІ GF(2^128)"""
        if x & (1 << 127):
            return ((x << 1) & ((1 << 128) - 1)) ^ self.r
        else:
            return (x << 1) & ((1 << 128) - 1)
    
    def _mul_gf(self, x, y):
        """РЈРјРЅРѕР¶РµРЅРёРµ РІ GF(2^128) СЃ РёСЃРїРѕР»СЊР·РѕРІР°РЅРёРµРј РїСЂРµРґРІС‹С‡РёСЃР»РµРЅРЅРѕР№ С‚Р°Р±Р»РёС†С‹"""
        z = 0
        
        # РђР»РіРѕСЂРёС‚Рј СѓРјРЅРѕР¶РµРЅРёСЏ СЃ РїСЂРµРґРІС‹С‡РёСЃР»РµРЅРЅРѕР№ С‚Р°Р±Р»РёС†РµР№
        for i in range(0, 128, 8):
            # РџРѕР»СѓС‡Р°РµРј Р±Р°Р№С‚ РёР· x (РЅР°С‡РёРЅР°СЏ СЃРѕ СЃС‚Р°СЂС€РµРіРѕ)
            byte_val = (x >> (120 - i)) & 0xFF
            z = self._int_xor(z, self.table[byte_val >> 4] << 4)
            z = self._mul2(z)
            z = self._int_xor(z, self.table[byte_val & 0x0F])
            if i < 120:
                for _ in range(8):
                    z = self._mul2(z)
        
        return z
    
    def _ghash(self, aad, ciphertext):
        """Р’С‹С‡РёСЃР»РµРЅРёРµ GHASH"""
        # РџРѕРґРіРѕС‚РѕРІРєР° РґР°РЅРЅС‹С…
        len_aad = len(aad)
        len_ct = len(ciphertext)
        
        # Р’С‹СЂР°РІРЅРёРІР°РЅРёРµ РґР°РЅРЅС‹С… РґРѕ РіСЂР°РЅРёС†С‹ 16 Р±Р°Р№С‚
        aad_padded = aad + bytes((-len_aad) % 16)
        ct_padded = ciphertext + bytes((-len_ct) % 16)
        
        # РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ
        y = 0
        
        # РћР±СЂР°Р±РѕС‚РєР° AAD
        for i in range(0, len(aad_padded), 16):
            block = aad_padded[i:i + 16]
            y = self._int_xor(y, self._bytes_to_int(block))
            y = self._mul_gf(y, self.table[1])
        
        # РћР±СЂР°Р±РѕС‚РєР° ciphertext
        for i in range(0, len(ct_padded), 16):
            block = ct_padded[i:i + 16]
            y = self._int_xor(y, self._bytes_to_int(block))
            y = self._mul_gf(y, self.table[1])
        
        # Р”РѕР±Р°РІР»РµРЅРёРµ РґР»РёРЅ (64 Р±РёС‚Р° РєР°Р¶РґР°СЏ)
        len_block = struct.pack('>QQ', len_aad * 8, len_ct * 8)
        y = self._int_xor(y, self._bytes_to_int(len_block))
        y = self._mul_gf(y, self.table[1])
        
        return y
    
    def _generate_initial_counter(self):
        """Р“РµРЅРµСЂР°С†РёСЏ РЅР°С‡Р°Р»СЊРЅРѕРіРѕ Р·РЅР°С‡РµРЅРёСЏ СЃС‡С‘С‚С‡РёРєР° РёР· nonce"""
        if len(self.nonce) == 12:
            # Р”Р»СЏ 12-Р±Р°Р№С‚РЅРѕРіРѕ nonce: J0 = nonce || 0x00000001
            j0 = self.nonce + b'\x00\x00\x00\x01'
        else:
            # Р”Р»СЏ РґСЂСѓРіРёС… СЂР°Р·РјРµСЂРѕРІ nonce: GHASH(nonce || padding)
            nonce_padded = self.nonce + bytes((-len(self.nonce)) % 16 + 8)
            len_block = struct.pack('>Q', len(self.nonce) * 8)
            j0 = self._ghash(b'', nonce_padded + len_block)
            j0 = self._int_to_bytes(j0)
        
        return j0
    
    def encrypt(self, plaintext, aad=b""):
        """
        РЁРёС„СЂРѕРІР°РЅРёРµ СЃ Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРµР№
        
        Args:
            plaintext (bytes): Р”Р°РЅРЅС‹Рµ РґР»СЏ С€РёС„СЂРѕРІР°РЅРёСЏ
            aad (bytes): РђСЃСЃРѕС†РёРёСЂРѕРІР°РЅРЅС‹Рµ РґР°РЅРЅС‹Рµ (РЅРµ С€РёС„СЂСѓСЋС‚СЃСЏ)
        
        Returns:
            bytes: nonce + ciphertext + tag
        """
        # Р“РµРЅРµСЂР°С†РёСЏ РЅР°С‡Р°Р»СЊРЅРѕРіРѕ СЃС‡С‘С‚С‡РёРєР°
        j0 = self._generate_initial_counter()
        
        # Р“РµРЅРµСЂР°С†РёСЏ РєР»СЋС‡Р° РґР»СЏ GHASH (H)
        h = self.aes.encrypt_block(bytes(16))
        h_int = self._bytes_to_int(h)
        self.table[1] = h_int
        self._precompute_table()  # РџРµСЂРµСЃС‡С‘С‚ С‚Р°Р±Р»РёС†С‹ СЃ РїСЂР°РІРёР»СЊРЅС‹Рј H
        
        # РЁРёС„СЂРѕРІР°РЅРёРµ РІ CTR СЂРµР¶РёРјРµ
        ctr = self._bytes_to_int(j0[:12]) << 32 | 2
        ciphertext = bytearray()
        
        for i in range(0, len(plaintext), self.block_size):
            # РЈРІРµР»РёС‡РµРЅРёРµ СЃС‡С‘С‚С‡РёРєР°
            ctr_block = (ctr + (i // self.block_size)).to_bytes(16, 'big')
            keystream = self.aes.encrypt_block(ctr_block)
            
            # XOR СЃ РѕС‚РєСЂС‹С‚С‹Рј С‚РµРєСЃС‚РѕРј
            block = plaintext[i:i + self.block_size]
            encrypted = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            ciphertext.extend(encrypted)
        
        ciphertext = bytes(ciphertext)
        
        # Р’С‹С‡РёСЃР»РµРЅРёРµ С‚РµРіР° Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё
        s = self.aes.encrypt_block(j0)
        s_int = self._bytes_to_int(s)
        
        ghash_result = self._ghash(aad, ciphertext)
        tag_int = self._int_xor(ghash_result, s_int)
        tag = self._int_to_bytes(tag_int)[:16]  # РћР±СЂРµР·Р°РµРј РґРѕ 16 Р±Р°Р№С‚
        
        # Р’РѕР·РІСЂР°С‰Р°РµРј nonce + ciphertext + tag
        return self.nonce + ciphertext + tag
    
    def decrypt(self, data, aad=b""):
        """
        Р Р°СЃС€РёС„СЂРѕРІР°РЅРёРµ СЃ РїСЂРѕРІРµСЂРєРѕР№ Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё
        
        Args:
            data (bytes): nonce + ciphertext + tag
            aad (bytes): РђСЃСЃРѕС†РёРёСЂРѕРІР°РЅРЅС‹Рµ РґР°РЅРЅС‹Рµ
        
        Returns:
            bytes: Р Р°СЃС€РёС„СЂРѕРІР°РЅРЅС‹Р№ С‚РµРєСЃС‚
        
        Raises:
            AuthenticationError: Р•СЃР»Рё Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёСЏ РЅРµ СѓРґР°Р»Р°СЃСЊ
        """
        if len(data) < 12 + 16:  # minimum: nonce(12) + tag(16)
            raise AuthenticationError("Р”Р°РЅРЅС‹Рµ СЃР»РёС€РєРѕРј РєРѕСЂРѕС‚РєРёРµ")
        
        # РР·РІР»РµС‡РµРЅРёРµ РєРѕРјРїРѕРЅРµРЅС‚РѕРІ
        nonce = data[:12]
        tag = data[-16:]
        ciphertext = data[12:-16]
        
        # РЈСЃС‚Р°РЅРѕРІРєР° nonce РґР»СЏ РїСЂРѕРІРµСЂРєРё
        self.nonce = nonce
        
        # Р“РµРЅРµСЂР°С†РёСЏ РЅР°С‡Р°Р»СЊРЅРѕРіРѕ СЃС‡С‘С‚С‡РёРєР°
        j0 = self._generate_initial_counter()
        
        # Р“РµРЅРµСЂР°С†РёСЏ РєР»СЋС‡Р° РґР»СЏ GHASH (H)
        h = self.aes.encrypt_block(bytes(16))
        h_int = self._bytes_to_int(h)
        self.table[1] = h_int
        self._precompute_table()
        
        # Р’С‹С‡РёСЃР»РµРЅРёРµ РѕР¶РёРґР°РµРјРѕРіРѕ С‚РµРіР°
        s = self.aes.encrypt_block(j0)
        s_int = self._bytes_to_int(s)
        
        ghash_result = self._ghash(aad, ciphertext)
        expected_tag_int = self._int_xor(ghash_result, s_int)
        expected_tag = self._int_to_bytes(expected_tag_int)[:16]
        
        # РџСЂРѕРІРµСЂРєР° С‚РµРіР° (РїРѕСЃС‚РѕСЏРЅРЅР°СЏ РїРѕ РІСЂРµРјРµРЅРё)
        if not self._constant_time_compare(tag, expected_tag):
            raise AuthenticationError("РћС€РёР±РєР° Р°СѓС‚РµРЅС‚РёС„РёРєР°С†РёРё: РЅРµРІРµСЂРЅС‹Р№ С‚РµРі")
        
        # Р Р°СЃС€РёС„СЂРѕРІР°РЅРёРµ РІ CTR СЂРµР¶РёРјРµ
        ctr = self._bytes_to_int(j0[:12]) << 32 | 2
        plaintext = bytearray()
        
        for i in range(0, len(ciphertext), self.block_size):
            # РЈРІРµР»РёС‡РµРЅРёРµ СЃС‡С‘С‚С‡РёРєР°
            ctr_block = (ctr + (i // self.block_size)).to_bytes(16, 'big')
            keystream = self.aes.encrypt_block(ctr_block)
            
            # XOR СЃ С€РёС„СЂС‚РµРєСЃС‚РѕРј
            block = ciphertext[i:i + self.block_size]
            decrypted = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            plaintext.extend(decrypted)
        
        return bytes(plaintext)
    
    def _constant_time_compare(self, a, b):
        """РЎСЂР°РІРЅРµРЅРёРµ СЃ РїРѕСЃС‚РѕСЏРЅРЅС‹Рј РІСЂРµРјРµРЅРµРј РґР»СЏ РїСЂРµРґРѕС‚РІСЂР°С‰РµРЅРёСЏ timing attacks"""
        if len(a) != len(b):
            return False
        
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

