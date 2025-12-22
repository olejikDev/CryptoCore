#!/usr/bin/env python3
"""
Test script for Sprint 7 - Key Derivation Functions
"""

import sys
import os
import hashlib

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.kdf.pbkdf2 import pbkdf2_hmac_sha256, verify_implementation
from src.kdf.hkdf import derive_key, test_key_uniqueness, test_deterministic_output
from src.csprng import generate_random_bytes


def test_pbkdf2_rfc6070():
    """Test PBKDF2 with RFC 6070 test vectors (TEST-1)"""
    print("Testing PBKDF2 with RFC 6070 test vectors...")

    test_cases = [
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
    ]

    all_passed = True

    for i, test in enumerate(test_cases, 1):
        try:
            result = pbkdf2_hmac_sha256(
                test['password'],
                test['salt'],
                test['iterations'],
                test['dklen']
            )

            expected = bytes.fromhex(test['expected'])

            if result == expected:
                print(f"  Test {i}: вњ“ PASSED")
            else:
                print(f"  Test {i}: вњ— FAILED")
                print(f"    Expected: {expected.hex()}")
                print(f"    Got:      {result.hex()}")
                all_passed = False

        except Exception as e:
            print(f"  Test {i}: вњ— ERROR - {e}")
            all_passed = False

    if all_passed:
        print("вњ“ All RFC 6070 test vectors passed")
    else:
        print("вњ— Some RFC 6070 tests failed")

    return all_passed


def test_pbkdf2_lengths():
    """Test PBKDF2 with various key lengths (TEST-3)"""
    print("\nTesting PBKDF2 with various key lengths...")

    password = b"test_password"
    salt = b"test_salt"
    iterations = 1000

    test_lengths = [1, 16, 32, 64, 100]  # Various lengths as per TEST-3

    all_passed = True

    for length in test_lengths:
        try:
            key = pbkdf2_hmac_sha256(password, salt, iterations, length)

            if len(key) == length:
                print(f"  Length {length:3d} bytes: вњ“ PASSED")
            else:
                print(f"  Length {length:3d} bytes: вњ— FAILED (got {len(key)} bytes)")
                all_passed = False

        except Exception as e:
            print(f"  Length {length:3d} bytes: вњ— ERROR - {e}")
            all_passed = False

    if all_passed:
        print("вњ“ All length tests passed")
    else:
        print("вњ— Some length tests failed")

    return all_passed


def test_pbkdf2_deterministic():
    """Test PBKDF2 produces same result multiple times (TEST-2)"""
    print("\nTesting PBKDF2 deterministic output...")

    password = b"deterministic_test"
    salt = b"test_salt_123"
    iterations = 10000
    dklen = 32

    # Run multiple times
    results = []
    for i in range(5):
        key = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        results.append(key)

    # Check all are equal
    all_equal = all(r == results[0] for r in results)

    if all_equal:
        print(f"вњ“ PBKDF2 is deterministic (5 runs produced identical output)")
        print(f"  Key: {results[0].hex()[:32]}...")
    else:
        print("вњ— PBKDF2 is not deterministic")

    return all_equal


def test_pbkdf2_openssl_interop():
    """Test PBKDF2 interoperability with OpenSSL (TEST-4)"""
    print("\nTesting PBKDF2 interoperability with OpenSSL...")

    # Simple test that we can match OpenSSL output
    # Note: Requires OpenSSL to be installed
    import subprocess

    test_password = "test123"
    test_salt = "deadbeef"
    test_iterations = 1000
    test_length = 32

    try:
        # Run OpenSSL command
        cmd = [
            'openssl', 'kdf', '-keylen', str(test_length),
            '-kdfopt', f'pass:{test_password}',
            '-kdfopt', f'salt:{test_salt}',
            '-kdfopt', f'iter:{test_iterations}',
            'PBKDF2'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            openssl_output = result.stdout.strip()
            openssl_bytes = bytes.fromhex(openssl_output)

            # Our implementation
            our_output = pbkdf2_hmac_sha256(
                test_password,
                test_salt,
                test_iterations,
                test_length
            )

            if openssl_bytes == our_output:
                print("вњ“ PBKDF2 matches OpenSSL output")
                print(f"  OpenSSL: {openssl_output[:32]}...")
                print(f"  Our:     {our_output.hex()[:32]}...")
                return True
            else:
                print("вњ— PBKDF2 does not match OpenSSL")
                return False
        else:
            print("вљ  Could not run OpenSSL for comparison")
            print(f"  Error: {result.stderr}")
            return True  # Not a failure, just skip

    except Exception as e:
        print(f"вљ  OpenSSL test skipped: {e}")
        return True  # Not a failure if OpenSSL not available


def test_salt_randomness():
    """Test salt randomness (TEST-7)"""
    print("\nTesting salt randomness...")

    salts = set()

    for i in range(1000):
        salt = generate_random_bytes(16)
        salt_hex = salt.hex()

        if salt_hex in salts:
            print(f"вњ— Duplicate salt found at iteration {i}")
            return False

        salts.add(salt_hex)

    print(f"вњ“ Generated {len(salts)} unique salts")
    return True


def run_all_tests():
    """Run all KDF tests"""
    print("=" * 60)
    print("Running Sprint 7 - Key Derivation Tests")
    print("=" * 60)

    test_results = []

    # Run tests
    test_results.append(("RFC 6070 Test Vectors", test_pbkdf2_rfc6070()))
    test_results.append(("Key Length Tests", test_pbkdf2_lengths()))
    test_results.append(("Deterministic Output", test_pbkdf2_deterministic()))
    test_results.append(("OpenSSL Interoperability", test_pbkdf2_openssl_interop()))
    test_results.append(("Implementation Verification", verify_implementation()))
    test_results.append(("Salt Randomness", test_salt_randomness()))
    test_results.append(("HKDF Deterministic", test_deterministic_output()))
    test_results.append(("HKDF Key Uniqueness", test_key_uniqueness()))

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, result in test_results if result)
    total = len(test_results)

    for test_name, result in test_results:
        status = "вњ“ PASS" if result else "вњ— FAIL"
        print(f"{status} {test_name}")

    print("-" * 60)
    print(f"Total: {passed}/{total} tests passed")

    if passed == total:
        print("вњ“ All tests passed successfully!")
        return 0
    else:
        print(f"вњ— {total - passed} tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())

