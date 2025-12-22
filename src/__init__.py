"""
CryptoCore - Cryptographic Toolkit
Sprint 7: Key Derivation Functions
"""

__version__ = "0.7.0"
__author__ = "CryptoCore Team"

from .crypto_core import CryptoCipher
from .csprng import generate_random_bytes, generate_aes_key, generate_aes_key_hex
from .file_io import FileHandler, read_file_safe, write_file_safe
from .kdf import (
    pbkdf2_hmac_sha256,
    pbkdf2_hmac_sha256_custom,
    derive_key,
    hkdf_extract,
    hkdf_expand,
    derive_multiple_keys
)