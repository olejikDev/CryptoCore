#!/usr/bin/env python3
"""
AES Cipher Implementation
Provides AES primitive for all modes of operation
"""

from Crypto.Cipher import AES as PyCryptoAES


class AES:
    """AES cipher wrapper class"""

    def __init__(self, key):
        """
        Initialize AES cipher

        Args:
            key (bytes): AES key (16, 24, or 32 bytes)
        """
        if len(key) not in [16, 24, 32]:
            raise ValueError(f"AES key must be 16, 24, or 32 bytes, got {len(key)}")

        self.key = key
        self.block_size = 16

        # Create AES primitive in ECB mode for block operations
        self._aes = PyCryptoAES.new(key, PyCryptoAES.MODE_ECB)

    def encrypt_block(self, block):
        """
        Encrypt a single block

        Args:
            block (bytes): 16-byte block to encrypt

        Returns:
            bytes: Encrypted block
        """
        if len(block) != self.block_size:
            raise ValueError(f"Block must be {self.block_size} bytes, got {len(block)}")

        return self._aes.encrypt(block)

    def decrypt_block(self, block):
        """
        Decrypt a single block

        Args:
            block (bytes): 16-byte block to decrypt

        Returns:
            bytes: Decrypted block
        """
        if len(block) != self.block_size:
            raise ValueError(f"Block must be {self.block_size} bytes, got {len(block)}")

        return self._aes.decrypt(block)

    def encrypt(self, data):
        """
        Encrypt data (full ECB mode)

        Args:
            data (bytes): Data to encrypt

        Returns:
            bytes: Encrypted data
        """
        # This is for backward compatibility
        # Actual ECB mode is implemented in ecb.py
        from Crypto.Util.Padding import pad
        padded_data = pad(data, self.block_size)

        result = b""
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]
            result += self.encrypt_block(block)

        return result

    def decrypt(self, data):
        """
        Decrypt data (full ECB mode)

        Args:
            data (bytes): Data to decrypt

        Returns:
            bytes: Decrypted data
        """
        # This is for backward compatibility
        from Crypto.Util.Padding import unpad

        if len(data) % self.block_size != 0:
            raise ValueError(f"Data length must be multiple of {self.block_size}")

        result = b""
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            result += self.decrypt_block(block)

        try:
            return unpad(result, self.block_size)
        except ValueError:
            # Return without unpadding if padding is invalid
            return result


def test_aes():
    """Test AES implementation"""
    # Test with 128-bit key
    key = b'\x00' * 16
    aes = AES(key)

    # Test block encryption
    plaintext = b'\x00' * 16
    ciphertext = aes.encrypt_block(plaintext)
    decrypted = aes.decrypt_block(ciphertext)

    assert decrypted == plaintext
    print("вњ“ AES block encryption/decryption test passed")

    # Test full encryption
    data = b"Hello, AES World!"
    encrypted = aes.encrypt(data)
    decrypted = aes.decrypt(encrypted)

    assert decrypted == data
    print("вњ“ AES full encryption/decryption test passed")

    return True


if __name__ == "__main__":
    test_aes()

