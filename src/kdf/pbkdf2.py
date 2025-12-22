"""
PBKDF2-HMAC-SHA256 implementation following RFC 2898.
Full implementation from scratch as required.
"""

import struct
import hmac as builtin_hmac
import hashlib
from typing import Union

# Р”Р»СЏ СЃРѕРІРјРµСЃС‚РёРјРѕСЃС‚Рё СЃ РЅР°С€РµР№ HMAC СЂРµР°Р»РёР·Р°С†РёРµР№ РёР· Sprint 5
try:
    from src.mac.hmac import HMAC as CustomHMAC
    HAS_CUSTOM_HMAC = True
except ImportError:
    HAS_CUSTOM_HMAC = False


def hmac_sha256_custom(key: bytes, msg: bytes) -> bytes:
    """
    HMAC-SHA256 using our implementation from Sprint 5.

    Args:
        key: HMAC key
        msg: Message to authenticate

    Returns:
        32-byte HMAC-SHA256 digest
    """
    if not HAS_CUSTOM_HMAC:
        raise ImportError("Custom HMAC implementation not available")

    hmac = CustomHMAC(key, 'sha256')
    return hmac.compute(msg)


def hmac_sha256_builtin(key: bytes, msg: bytes) -> bytes:
    """
    HMAC-SHA256 using Python's built-in implementation.
    Used for verification.
    """
    return builtin_hmac.new(key, msg, hashlib.sha256).digest()


def pbkdf2_hmac_sha256(
        password: Union[str, bytes],
        salt: Union[str, bytes],
        iterations: int,
        dklen: int,
        use_custom_hmac: bool = False
) -> bytes:
    """
    PBKDF2-HMAC-SHA256 key derivation function (from scratch).

    Args:
        password: Password (string or bytes)
        salt: Salt (string or bytes)
        iterations: Number of iterations (must be >= 1)
        dklen: Desired key length in bytes
        use_custom_hmac: Use our HMAC implementation (default: built-in for performance)

    Returns:
        Derived key as bytes

    Raises:
        ValueError: If parameters are invalid

    Implementation follows RFC 2898:
    DK = T1 || T2 || ... || Tdklen/hlen
    Ti = F(P, S, c, i) where F(P, S, c, i) = U1 ^ U2 ^ ... ^ Uc
    U1 = PRF(P, S || INT(i))
    Uj = PRF(P, Uj-1)
    """
    # Convert inputs
    if isinstance(password, str):
        password = password.encode('utf-8')

    if isinstance(salt, str):
        # Check if salt is hex string
        try:
            salt = bytes.fromhex(salt)
        except ValueError:
            salt = salt.encode('utf-8')

    # Validate parameters
    if iterations < 1:
        raise ValueError("Iterations must be >= 1")
    if dklen < 1:
        raise ValueError("Key length must be >= 1")
    if dklen > (2**32 - 1) * 32:  # SHA-256 output is 32 bytes
        raise ValueError("Key length too large")

    # Choose HMAC function
    if use_custom_hmac and HAS_CUSTOM_HMAC:
        prf = hmac_sha256_custom
    else:
        prf = hmac_sha256_builtin

    hlen = 32  # SHA-256 output size
    blocks_needed = (dklen + hlen - 1) // hlen
    derived_key = bytearray()

    for block_index in range(1, blocks_needed + 1):
        # U1 = PRF(P, S || INT_32_BE(i))
        block_salt = salt + struct.pack('>I', block_index)

        # Initialize with U1
        u_current = prf(password, block_salt)
        block_acc = bytearray(u_current)

        # Compute U2 through Uc
        for _ in range(2, iterations + 1):
            u_current = prf(password, u_current)

            # XOR with accumulated value
            for j in range(hlen):
                block_acc[j] ^= u_current[j]

        derived_key.extend(block_acc)

    # Return exactly dklen bytes
    return bytes(derived_key[:dklen])


def pbkdf2_hmac_sha256_fast(
        password: Union[str, bytes],
        salt: Union[str, bytes],
        iterations: int,
        dklen: int
) -> bytes:
    """
    Fast PBKDF2-HMAC-SHA256 using Python's hashlib.
    Used as reference and for performance.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')

    if isinstance(salt, str):
        try:
            salt = bytes.fromhex(salt)
        except ValueError:
            salt = salt.encode('utf-8')

    return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)


def verify_implementation() -> bool:
    """
    Verify our implementation against Python's built-in PBKDF2.

    Returns:
        True if implementations match, False otherwise
    """
    test_vectors = [
        # RFC 6070 test vectors
        {
            'password': b'password',
            'salt': b'salt',
            'iterations': 1,
            'dklen': 20,
            'expected': '0c60c80f961f0e71f3a9b524af6012062fe037a6'
        },
        {
            'password': b'password',
            'salt': b'salt',
            'iterations': 2,
            'dklen': 20,
            'expected': 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'
        },
        {
            'password': b'password',
            'salt': b'salt',
            'iterations': 4096,
            'dklen': 20,
            'expected': '4b007901b765489abead49d926f721d065a429c1'
        },
        {
            'password': b'passwordPASSWORDpassword',
            'salt': b'saltSALTsaltSALTsaltSALTsaltSALTsalt',
            'iterations': 4096,
            'dklen': 25,
            'expected': '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'
        },
        # Additional test cases
        {
            'password': 'test',
            'salt': '73616c74',
            'iterations': 1000,
            'dklen': 32,
            'expected': None  # Will compute with built-in
        }
    ]

    all_pass = True

    for i, test in enumerate(test_vectors):
        try:
            # Get expected value
            if test['expected'] is not None:
                expected = bytes.fromhex(test['expected'])
            else:
                expected = pbkdf2_hmac_sha256_fast(
                    test['password'],
                    test['salt'],
                    test['iterations'],
                    test['dklen']
                )

            # Our implementation
            result = pbkdf2_hmac_sha256(
                test['password'],
                test['salt'],
                test['iterations'],
                test['dklen'],
                use_custom_hmac=False  # Use built-in HMAC for verification
            )

            if result != expected:
                print(f"Test {i+1} failed")
                print(f"Expected: {expected.hex()}")
                print(f"Got:      {result.hex()}")
                all_pass = False

        except Exception as e:
            print(f"Test {i+1} error: {e}")
            all_pass = False

    if all_pass:
        print("All PBKDF2 tests passed вњ“")

    return all_pass


def benchmark_iterations():
    """Benchmark different iteration counts as required in TEST-8."""
    import time

    password = b"benchmark_password"
    salt = b"benchmark_salt"
    test_cases = [
        ("10k iterations", 10000, 32),
        ("100k iterations", 100000, 32),
        ("1M iterations", 1000000, 32),
    ]

    print("PBKDF2 Performance Benchmark:")
    print("-" * 50)

    for name, iterations, dklen in test_cases:
        start = time.time()
        pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        elapsed = time.time() - start

        print(f"{name}: {elapsed:.2f} seconds ({iterations/elapsed:,.0f} iterations/sec)")

    print("-" * 50)


if __name__ == "__main__":
    # Run verification
    verify_implementation()

    # Run benchmark
    benchmark_iterations()

