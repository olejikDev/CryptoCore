"""
Test key hierarchy (HKDF-style) implementation.
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kdf.hkdf import derive_key


def test_key_hierarchy_deterministic():
    """Test that derive_key is deterministic"""
    master = b'0' * 32
    context = "encryption"

    key1 = derive_key(master, context, 32)
    key2 = derive_key(master, context, 32)

    if key1 == key2:
        print("✓ Deterministic test passed")
        return True
    else:
        print("✗ Deterministic test failed")
        print(f"  First:  {key1.hex()[:32]}...")
        print(f"  Second: {key2.hex()[:32]}...")
        return False


def test_context_separation():
    """Test that different contexts produce different keys"""
    master = b'1' * 32

    key1 = derive_key(master, "encryption", 32)
    key2 = derive_key(master, "authentication", 32)
    key3 = derive_key(master, "key_encryption", 32)

    # All should be different
    if key1 != key2 and key1 != key3 and key2 != key3:
        print("✓ Context separation test passed")
        return True
    else:
        print("✗ Context separation test failed")
        print(f"  Key1 (encryption): {key1.hex()[:16]}...")
        print(f"  Key2 (auth):       {key2.hex()[:16]}...")
        print(f"  Key3 (key_enc):    {key3.hex()[:16]}...")
        return False


def test_variable_length():
    """Test derive_key with various lengths"""
    master = b'2' * 32
    context = "test"

    test_cases = [1, 16, 32, 64, 100, 256]
    all_passed = True

    for length in test_cases:
        key = derive_key(master, context, length)

        if len(key) == length:
            print(f"✓ Length test {length} bytes passed")
        else:
            print(f"✗ Length test {length} bytes failed")
            print(f"  Expected {length} bytes, got {len(key)} bytes")
            all_passed = False

    return all_passed


def test_master_key_sensitivity():
    """Test that small changes in master key produce completely different derived keys"""
    master1 = b'0' * 32
    master2 = b'0' * 31 + b'1'  # Change last byte

    key1 = derive_key(master1, "context", 32)
    key2 = derive_key(master2, "context", 32)

    # They should be completely different
    if key1 != key2:
        # Also check they're not just slightly different
        diff_bytes = sum(a != b for a, b in zip(key1, key2))
        if diff_bytes > 20:  # At least 20 bytes should differ
            print(f"✓ Master key sensitivity test passed ({diff_bytes}/32 bytes differ)")
            return True
        else:
            print(f"✗ Master key sensitivity test failed (only {diff_bytes}/32 bytes differ)")
            return False
    else:
        print("✗ Master key sensitivity test failed (keys are identical!)")
        return False


if __name__ == "__main__":
    print("Running Key Hierarchy tests...")
    print("=" * 50)

    all_passed = True

    if not test_key_hierarchy_deterministic():
        all_passed = False

    print("\n" + "=" * 50)
    if not test_context_separation():
        all_passed = False

    print("\n" + "=" * 50)
    if not test_variable_length():
        all_passed = False

    print("\n" + "=" * 50)
    if not test_master_key_sensitivity():
        all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("✅ All Key Hierarchy tests passed!")
    else:
        print("❌ Some Key Hierarchy tests failed!")
        sys.exit(1)