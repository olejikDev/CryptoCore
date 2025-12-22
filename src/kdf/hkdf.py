"""
HKDF (HMAC-based Key Derivation Function) implementation.
Simplified version for key hierarchy as specified in Sprint 7.
"""

import struct
import hmac as builtin_hmac
import hashlib
from typing import Union, List

# Р”Р»СЏ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё СЃ РЅР°С€РµР№ HMAC СЂРµР°Р»РёР·Р°С†РёРµР№
try:
    from src.mac.hmac import HMAC as CustomHMAC
    HAS_CUSTOM_HMAC = True
except ImportError:
    HAS_CUSTOM_HMAC = False


def hmac_sha256(key: bytes, msg: bytes, use_custom: bool = False) -> bytes:
    """
    HMAC-SHA256 wrapper.

    Args:
        key: HMAC key
        msg: Message
        use_custom: Use custom implementation

    Returns:
        32-byte HMAC digest
    """
    if use_custom and HAS_CUSTOM_HMAC:
        hmac = CustomHMAC(key, 'sha256')
        return hmac.compute(msg)
    else:
        return builtin_hmac.new(key, msg, hashlib.sha256).digest()


def derive_key(
        master_key: bytes,
        context: Union[str, bytes],
        length: int = 32,
        use_custom_hmac: bool = False
) -> bytes:
    """
    Derive a key from a master key using deterministic HMAC-based method.

    Args:
        master_key: Master key bytes
        context: Context string (identifies key purpose)
        length: Desired key length in bytes
        use_custom_hmac: Use custom HMAC implementation

    Returns:
        Derived key as bytes

    Derivation formula: HMAC(master_key, context || counter)
    Different contexts produce completely different keys.
    """
    if isinstance(context, str):
        context = context.encode('utf-8')

    if length <= 0:
        raise ValueError("Key length must be positive")

    if len(master_key) == 0:
        raise ValueError("Master key cannot be empty")

    derived = b''
    counter = 1

    while len(derived) < length:
        # T_i = HMAC(master_key, context || INT_32_BE(counter))
        counter_bytes = struct.pack('>I', counter)
        block = hmac_sha256(master_key, context + counter_bytes, use_custom_hmac)

        derived += block
        counter += 1

    # Return exactly the requested length
    return derived[:length]


def hkdf_extract(salt: bytes, ikm: bytes, use_custom_hmac: bool = False) -> bytes:
    """
    HKDF-Extract step.

    Args:
        salt: Optional salt (if empty, uses zero salt)
        ikm: Input key material
        use_custom_hmac: Use custom HMAC implementation

    Returns:
        Pseudo-random key (PRK)
    """
    if salt is None or len(salt) == 0:
        # Use zero salt as per RFC 5869
        salt = b'\x00' * 32  # SHA-256 hash length

    return hmac_sha256(salt, ikm, use_custom_hmac)


def hkdf_expand(prk: bytes, info: bytes, length: int, use_custom_hmac: bool = False) -> bytes:
    """
    HKDF-Expand step.

    Args:
        prk: Pseudo-random key from extract step
        info: Context and application specific information
        length: Length of output keying material in bytes
        use_custom_hmac: Use custom HMAC implementation

    Returns:
        Output keying material

    Raises:
        ValueError: If output length too large
    """
    hlen = 32  # SHA-256 output size
    n = (length + hlen - 1) // hlen

    if n > 255:
        raise ValueError("Output length too large (max: 255 * 32 = 8160 bytes)")

    okm = b''
    previous = b''

    for i in range(1, n + 1):
        # T(i) = HMAC-Hash(PRK, T(i-1) | info | INT_8(i))
        current_input = previous + info + bytes([i])
        current = hmac_sha256(prk, current_input, use_custom_hmac)
        okm += current
        previous = current

    return okm[:length]


def hkdf_derive(
        ikm: bytes,
        salt: bytes = None,
        info: bytes = b'',
        length: int = 32,
        use_custom_hmac: bool = False
) -> bytes:
    """
    Full HKDF (Extract then Expand).

    Args:
        ikm: Input key material
        salt: Optional salt
        info: Context information
        length: Output length in bytes
        use_custom_hmac: Use custom HMAC implementation

    Returns:
        Derived key material
    """
    prk = hkdf_extract(salt, ikm, use_custom_hmac)
    return hkdf_expand(prk, info, length, use_custom_hmac)


def derive_multiple_keys(
        master_key: bytes,
        context: Union[str, bytes],
        num_keys: int = 1,
        key_length: int = 32,
        use_custom_hmac: bool = False
) -> List[bytes]:
    """
    Derive multiple unique keys from a master key and context.

    Args:
        master_key: Master key bytes
        context: Base context string
        num_keys: Number of keys to derive
        key_length: Length of each key in bytes
        use_custom_hmac: Use custom HMAC implementation

    Returns:
        List of derived keys

    Guarantee:
        All returned keys will be unique (with cryptographic probability)
    """
    if isinstance(context, str):
        context = context.encode('utf-8')

    if num_keys < 1:
        raise ValueError("Number of keys must be >= 1")

    keys = []

    for i in range(num_keys):
        # Add index to context for uniqueness
        unique_context = context + struct.pack('>I', i)
        key = derive_key(master_key, unique_context, key_length, use_custom_hmac)
        keys.append(key)

    return keys


def test_key_uniqueness():
    """Test for key uniqueness as required in TEST-6."""
    import secrets

    master_key = secrets.token_bytes(32)
    base_context = b"test_context"

    # Test different contexts produce different keys
    key1 = derive_key(master_key, "encryption", 32)
    key2 = derive_key(master_key, "authentication", 32)
    key3 = derive_key(master_key, "key_wrapping", 32)

    assert key1 != key2 != key3, "Different contexts should produce different keys"

    # Test multiple keys from same context
    keys = derive_multiple_keys(master_key, base_context, 100, 32)
    keys_set = set(k.hex() for k in keys)

    assert len(keys_set) == 100, "All derived keys should be unique"

    print("вњ“ Key uniqueness tests passed")
    print(f"  Context separation: {key1.hex()[:16]}... != {key2.hex()[:16]}...")
    print(f"  Generated {len(keys_set)} unique keys")

    return True


def test_deterministic_output():
    """Test deterministic output as required in TEST-5."""
    master_key = b"\x00" * 32
    context = "test"

    key1 = derive_key(master_key, context, 32)
    key2 = derive_key(master_key, context, 32)
    key3 = derive_key(master_key, context, 32)

    assert key1 == key2 == key3, "Same inputs should produce same output"

    print("вњ“ Deterministic output test passed")
    return True


if __name__ == "__main__":
    print("Running HKDF tests...")
    test_deterministic_output()
    test_key_uniqueness()

