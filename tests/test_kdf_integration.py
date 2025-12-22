"""
Integration tests for KDF functionality with CLI.
"""
import subprocess
import tempfile
import os
import sys


def test_cli_derive_basic():
    """Test basic CLI derive command"""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("test output")
        output_file = f.name

    try:
        # Test with explicit salt
        result = subprocess.run(
            [
                sys.executable, 'cli_parser.py', 'derive',
                '--password', 'testpassword',
                '--salt', '00112233445566778899aabbccddeeff',
                '--iterations', '1000',
                '--length', '32'
            ],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            print("вњ“ Basic CLI derive test passed")

            # Parse output: KEY_HEX SALT_HEX
            parts = result.stdout.strip().split()
            if len(parts) == 2:
                key_hex, salt_hex = parts
                if len(key_hex) == 64:  # 32 bytes in hex
                    print("  Output format correct")
                else:
                    print(f"  Unexpected key length: {len(key_hex)} chars")

            return True
        else:
            print("вњ— Basic CLI derive test failed")
            print(f"  Error: {result.stderr}")
            return False

    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)


def test_cli_derive_with_output():
    """Test CLI derive with file output"""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        output_file = f.name

    try:
        result = subprocess.run(
            [
                sys.executable, 'cli_parser.py', 'derive',
                '--password', 'test',
                '--salt', '1234567890abcdef',
                '--iterations', '100',
                '--length', '16',
                '--output', output_file
            ],
            capture_output=True,
            text=True
        )

        if result.returncode == 0 and os.path.exists(output_file):
            with open(output_file, 'rb') as f:
                key_bytes = f.read()

            if len(key_bytes) == 16:
                print("вњ“ CLI derive with output file test passed")
                print(f"  Key written: {key_bytes.hex()}")
                return True
            else:
                print(f"вњ— Wrong key length: {len(key_bytes)} bytes")
                return False
        else:
            print("вњ— CLI derive with output file test failed")
            return False

    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)


def test_cli_key_hierarchy():
    """Test CLI key hierarchy mode"""
    result = subprocess.run(
        [
            sys.executable, 'cli_parser.py', 'derive',
            '--master-key', '00' * 32,  # 32 bytes of zeros
            '--context', 'encryption',
            '--length', '32'
        ],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print("вњ“ CLI key hierarchy test passed")
        print(f"  Output: {result.stdout.strip()[:64]}...")
        return True
    else:
        print("вњ— CLI key hierarchy test failed")
        print(f"  Error: {result.stderr}")
        return False


if __name__ == "__main__":
    print("Running KDF Integration tests...")
    print("=" * 50)

    all_passed = True

    if not test_cli_derive_basic():
        all_passed = False

    print("\n" + "=" * 50)
    if not test_cli_derive_with_output():
        all_passed = False

    print("\n" + "=" * 50)
    if not test_cli_key_hierarchy():
        all_passed = False

    print("\n" + "=" * 50)
    if all_passed:
        print("вњ… All KDF Integration tests passed!")
    else:
        print("вќЊ Some KDF Integration tests failed!")
        sys.exit(1)

