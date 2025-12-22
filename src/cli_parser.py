import argparse
import sys
import os
import warnings
from src.file_io import read_file, write_file, read_file_with_iv_or_none
from src.csprng import generate_random_bytes

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def parse_args():
    parser = argparse.ArgumentParser(
        description="CryptoCore - Minimalist Cryptographic Provider",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  ENCRYPTION/DECRYPTION:
    Encryption with auto-generated key:
      cryptocore encrypt --algorithm aes --mode ctr --encrypt \\
        --input plaintext.txt --output ciphertext.bin

    Encryption with provided key:
      cryptocore encrypt --algorithm aes --mode cbc --encrypt \\
        --key 00112233445566778899aabbccddeeff \\
        --input plaintext.txt --output ciphertext.bin

    Decryption (key must be provided):
      cryptocore encrypt --algorithm aes --mode cbc --decrypt \\
        --key 00112233445566778899aabbccddeeff \\
        --input ciphertext.bin --output decrypted.txt

  HASHING:
    Compute SHA-256 hash:
      cryptocore dgst --algorithm sha256 --input file.txt

    Compute SHA3-256 hash and save to file:
      cryptocore dgst --algorithm sha3-256 --input document.pdf \\
        --output hash.txt

  HMAC (Message Authentication Code):
    Generate HMAC-SHA256:
      cryptocore dgst --algorithm sha256 --hmac \\
        --key 00112233445566778899aabbccddeeff \\
        --input secret.txt

    Generate HMAC and save to file:
      cryptocore dgst --algorithm sha256 --hmac \\
        --key 00112233445566778899aabbccddeeff \\
        --input backup.tar --output backup.hmac

    Verify HMAC:
      cryptocore dgst --algorithm sha256 --hmac \\
        --key 00112233445566778899aabbccddeeff \\
        --input backup.tar --verify backup.hmac

    Note: For decryption with explicit IV:
      cryptocore encrypt --algorithm aes --mode cbc --decrypt \\
        --key 00112233445566778899aabbccddeeff \\
        --iv aabbccddeeff00112233445566778899 \\
        --input ciphertext_only.bin --output decrypted.txt

        # GCM Encryption with AAD
    cryptocore encrypt --algorithm aes --mode gcm --encrypt \\
      --key 00112233445566778899aabbccddeeff \\
      --input plaintext.txt --output ciphertext.gcm \\
      --aad aabbccddeeff00112233445566778899

    # GCM Decryption (AAD must match)
    cryptocore encrypt --algorithm aes --mode gcm --decrypt \\
      --key 00112233445566778899aabbccddeeff \\
      --input ciphertext.gcm --output decrypted.txt \\
      --aad aabbccddeeff00112233445566778899

    # Encrypt-then-MAC (separate encryption and MAC keys)
    cryptocore encrypt --algorithm aes --mode etm --encrypt \\
      --key 00112233445566778899aabbccddeeff \\
      --mac-key 33445566778899aabbccddeeff00112233445566778899aabbcc \\
      --input data.txt --output data.etm \\
      --aad "context information"

    # Decrypt and verify Encrypt-then-MAC
    cryptocore encrypt --algorithm aes --mode etm --decrypt \\
      --key 00112233445566778899aabbccddeeff \\
      --mac-key 33445566778899aabbccddeeff00112233445566778899aabbcc \\
      --input data.etm --output verified.txt \\
      --aad "context information"

      KEY DERIVATION:
    # Derive key with specified salt
    cryptocore derive --password "MySecurePassword123!" \\
      --salt a1b2c3d4e5f601234567890123456789 \\
      --iterations 100000 --length 32

    # Derive key with auto-generated salt
    cryptocore derive --password "AnotherPassword" \\
      --iterations 500000 --length 16

    # Derive key and save to file
    cryptocore derive --password "app_key" \\
      --iterations 10000 --length 32 \\
      --output secret_key.bin

    # Read password from file
    cryptocore derive --password-file password.txt \\
      --iterations 100000 --length 32
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands", required=True)

    # ================== ENCRYPT/DECRYPT COMMAND ==================
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt or decrypt a file")

    encrypt_parser.add_argument(
        "--algorithm",
        required=True,
        choices=["aes"],
        help="Cipher algorithm (currently only 'aes' supported)"
    )

    encrypt_parser.add_argument(
        "--mode",
        required=True,
        choices=["ecb", "cbc", "cfb", "ofb", "ctr", "gcm", "etm"],
        help="Mode of operation"
    )

    operation_group = encrypt_parser.add_mutually_exclusive_group(required=True)
    operation_group.add_argument("--encrypt", action="store_true", help="Perform encryption")
    operation_group.add_argument("--decrypt", action="store_true", help="Perform decryption")

    encrypt_parser.add_argument(
        "--key",
        help="Encryption key as hexadecimal string (16 bytes = 32 hex chars for AES-128). "
             "Optional for encryption (will be auto-generated). Required for decryption."
    )

    encrypt_parser.add_argument(
        "--iv",
        help="Initialization Vector as hexadecimal string (16 bytes = 32 hex chars). "
             "Only used for decryption. For encryption, a random IV is generated."
    )

    encrypt_parser.add_argument(
        "--aad",
        help="Additional Authenticated Data as hexadecimal string. Used for GCM and Encrypt-then-MAC modes."
    )

    encrypt_parser.add_argument(
        "--mac-key",
        help="MAC key for Encrypt-then-MAC mode as hexadecimal string. Required for etm mode."
    )

    encrypt_parser.add_argument(
        "--input",
        required=True,
        help="Input file path"
    )

    encrypt_parser.add_argument(
        "--output",
        help="Output file path (optional)"
    )

    # ================== HASH COMMAND (DGST) ==================
    dgst_parser = subparsers.add_parser("dgst", help="Compute message digest (hash)")

    dgst_parser.add_argument(
        "--algorithm",
        required=True,
        choices=["sha256", "sha3-256"],
        help="Hash algorithm"
    )

    dgst_parser.add_argument(
        "--input",
        required=True,
        help="Input file to hash"
    )

    dgst_parser.add_argument(
        "--output",
        help="Output file for hash (optional)"
    )

    dgst_parser.add_argument(
        "--hmac",
        action="store_true",
        help="Enable HMAC mode (requires --key)"
    )

    dgst_parser.add_argument(
        "--key",
        help="HMAC key as hexadecimal string (required when using --hmac)"
    )

    dgst_parser.add_argument(
        "--verify",
        help="Verify HMAC against file containing expected value (requires --hmac and --key)"
    )

    # ================== KEY DERIVATION COMMAND ==================
    derive_parser = subparsers.add_parser("derive", help="Derive cryptographic keys from passwords or other keys")

    derive_parser.add_argument(
        "--password", "-p",
        help="Password string (quote if contains special characters)"
    )

    derive_parser.add_argument(
        "--password-file", "-P",
        help="Read password from file instead of command line"
    )

    derive_parser.add_argument(
        "--salt", "-s",
        help="Salt as hexadecimal string. If not provided, a random 16-byte salt will be generated."
    )

    derive_parser.add_argument(
        "--iterations", "-i",
        type=int,
        default=100000,
        help="Number of PBKDF2 iterations (default: 100000)"
    )

    derive_parser.add_argument(
        "--length", "-l",
        type=int,
        default=32,
        help="Desired key length in bytes (default: 32)"
    )

    derive_parser.add_argument(
        "--algorithm", "-a",
        choices=["pbkdf2"],
        default="pbkdf2",
        help="KDF algorithm (default: pbkdf2)"
    )

    derive_parser.add_argument(
        "--output", "-o",
        help="Output file to write derived key (binary format)"
    )

    derive_parser.add_argument(
        "--no-print",
        action="store_true",
        help="Suppress output to stdout"
    )

    return parser.parse_args()


def check_weak_key(key_bytes):
    """Check if key is weak (all zeros, sequential bytes, etc.)"""
    if len(key_bytes) != 16:
        return False, None

    # Check for all zeros
    if all(b == 0 for b in key_bytes):
        return True, "Key contains all zero bytes"

    # Check for all same byte
    if all(b == key_bytes[0] for b in key_bytes):
        return True, "Key contains all identical bytes"

    # Check for sequential hex pairs
    is_hex_pairs = True
    for i in range(0, 32, 2):
        hex_pair = key_bytes.hex()[i:i + 2]

        if hex_pair[0] != hex_pair[1]:
            is_hex_pairs = False
            break

        expected_value = i // 2
        if int(hex_pair, 16) != expected_value:
            is_hex_pairs = False
            break

    if is_hex_pairs:
        return True, "Key contains sequential repeating hex pairs (00, 11, 22, ..., ff)"

    # Check for simple sequential bytes
    is_sequential = True
    for i in range(16):
        if key_bytes[i] != i:
            is_sequential = False
            break

    if is_sequential:
        return True, "Key contains simple sequential bytes (0x00, 0x01, 0x02, ...)"

    # Check for reverse sequential
    is_reverse = True
    for i in range(16):
        if key_bytes[i] != (0xff - i):
            is_reverse = False
            break

    if is_reverse:
        return True, "Key contains reverse sequential bytes (0xff, 0xfe, 0xfd, ...)"

    # Check for low entropy
    unique_bytes = len(set(key_bytes))
    if unique_bytes < 4:
        return True, f"Key has very low entropy (only {unique_bytes} unique bytes)"
    elif unique_bytes < 8:
        return True, f"Key has low entropy (only {unique_bytes} unique bytes)"

    # Check for repeating patterns
    for pattern_size in [1, 2, 4, 8]:
        if 16 % pattern_size == 0:
            pattern = key_bytes[:pattern_size]
            repetitions = 16 // pattern_size
            expected = pattern * repetitions

            if key_bytes == expected:
                return True, f"Key contains repeating {pattern_size}-byte pattern"

    # Known weak keys
    weak_keys = [
        bytes.fromhex("00000000000000000000000000000000"),
        bytes.fromhex("ffffffffffffffffffffffffffffffff"),
        bytes.fromhex("0123456789abcdef0123456789abcdef"),
        bytes.fromhex("fedcba9876543210fedcba9876543210"),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
    ]

    if key_bytes in weak_keys:
        return True, "Key matches known weak AES key pattern"

    return False, None


def validate_key(key_hex, is_encrypt=True):
    """Validate and convert hex key to bytes, or generate if not provided"""
    if is_encrypt and not key_hex:
        print(f"[INFO] No key provided, generating secure random key...", file=sys.stderr)
        try:
            key_bytes = generate_random_bytes(16)
            key_hex = key_bytes.hex()
            print(f"[INFO] Generated random key: {key_hex}")
            return key_bytes
        except Exception as e:
            print(f"Error: Failed to generate random key: {e}", file=sys.stderr)
            sys.exit(1)

    if not key_hex:
        print("Error: Key is required for decryption", file=sys.stderr)
        sys.exit(1)

    try:
        if key_hex.startswith('0x') or key_hex.startswith('0X'):
            key_hex = key_hex[2:]

        key_bytes = bytes.fromhex(key_hex)

        if len(key_bytes) != 16:
            print(f"Error: AES-128 requires 16-byte key (32 hex characters)", file=sys.stderr)
            print(f"       Received: {key_hex} ({len(key_hex)} chars = {len(key_bytes)} bytes)", file=sys.stderr)
            sys.exit(1)

        # Check for weak key
        is_weak, reason = check_weak_key(key_bytes)
        if is_weak:
            warnings.warn(
                f"Warning: Potentially weak key detected: {reason}. "
                f"Consider using a stronger key for better security.",
                UserWarning
            )

        return key_bytes
    except ValueError as e:
        print(f"Error: Invalid key format", file=sys.stderr)
        print(f"       Key must be a 32-character hexadecimal string (0-9, a-f)", file=sys.stderr)
        print(f"       Example: 00112233445566778899aabbccddeeff", file=sys.stderr)
        sys.exit(1)


def validate_iv(iv_hex, mode, encrypt):
    """Validate IV if provided"""
    if iv_hex is None:
        return None

    try:
        if iv_hex.startswith('0x') or iv_hex.startswith('0X'):
            iv_hex = iv_hex[2:]

        iv_bytes = bytes.fromhex(iv_hex)

        # Different IV length for different modes
        if mode == "gcm":
            required_len = 12  # GCM uses 12-byte nonce
            error_msg = "Nonce must be 12 bytes (24 hex characters) for GCM"
        else:
            required_len = 16  # Other modes use 16-byte IV
            error_msg = "IV must be 16 bytes (32 hex characters)"

        if len(iv_bytes) != required_len:
            print(f"Error: {error_msg}", file=sys.stderr)
            print(f"       Received: {iv_hex} ({len(iv_hex)} chars = {len(iv_bytes)} bytes)", file=sys.stderr)
            sys.exit(1)

        # Warning if IV provided for encryption
        if encrypt and mode != "gcm":  # GCM always generates nonce
            warnings.warn(
                f"Warning: IV provided for encryption in {mode} mode. "
                f"A random IV will be generated instead.",
                UserWarning
            )
            return None
        else:
            return iv_bytes

    except ValueError as e:
        print(f"Error: Invalid IV/Nonce format", file=sys.stderr)
        if mode == "gcm":
            print(f"       Nonce must be a 24-character hexadecimal string", file=sys.stderr)
        else:
            print(f"       IV must be a 32-character hexadecimal string", file=sys.stderr)
        sys.exit(1)


def validate_aad(aad_hex):
    """Validate AAD if provided"""
    if aad_hex is None:
        return b""

    try:
        if aad_hex.startswith('0x') or aad_hex.startswith('0X'):
            aad_hex = aad_hex[2:]

        aad_bytes = bytes.fromhex(aad_hex)
        return aad_bytes
    except ValueError as e:
        print(f"Error: Invalid AAD format", file=sys.stderr)
        print(f"       AAD must be a hexadecimal string", file=sys.stderr)
        sys.exit(1)


def validate_derive_args(args):
    """Validate derive command arguments"""
    if not args.password and not args.password_file:
        print("Error: Either --password or --password-file must be specified", file=sys.stderr)
        sys.exit(1)

    if args.password and args.password_file:
        print("Error: Cannot use both --password and --password-file", file=sys.stderr)
        sys.exit(1)

    if args.iterations < 1:
        print("Error: Iterations must be >= 1", file=sys.stderr)
        sys.exit(1)

    if args.length < 1:
        print("Error: Key length must be >= 1", file=sys.stderr)
        sys.exit(1)

    if args.salt:
        try:
            salt_hex = args.salt
            if salt_hex.startswith('0x') or salt_hex.startswith('0X'):
                salt_hex = salt_hex[2:]

            bytes.fromhex(salt_hex)
        except ValueError:
            print(f"Error: Invalid salt format", file=sys.stderr)
            print(f"       Salt must be a hexadecimal string", file=sys.stderr)
            sys.exit(1)


def get_mode_class(mode):
    """Return the appropriate mode class"""
    from src.modes import MODES

    if mode in MODES:
        return MODES[mode]

    print(f"Error: Mode '{mode}' not implemented", file=sys.stderr)
    sys.exit(1)


def get_default_output_filename(input_file, encrypt):
    """Generate default output filename"""
    if encrypt:
        return input_file + ".enc"
    else:
        if input_file.endswith('.enc'):
            return input_file[:-4] + ".dec"
        else:
            return input_file + ".dec"


def handle_gcm_mode(encrypt, key, input_file, output_file, aad, iv=None):
    """Handle GCM mode"""
    try:
        from src.modes.gcm import GCM, AuthenticationError

        if encrypt:
            # GCM ENCRYPTION
            gcm = GCM(key)
            data = read_file(input_file)

            # Encrypt with AAD
            ciphertext = gcm.encrypt(data, aad)

            # Write result (nonce + ciphertext + tag)
            write_file(output_file, ciphertext)

            print(f"Success: GCM encrypted data written to {output_file}")
            print(f"Nonce used (hex): {gcm.nonce.hex()}")
            if aad:
                print(f"AAD used (hex): {aad.hex()}")
            print(f"Tag length: 16 bytes")

            print(f"Total ciphertext length: {len(ciphertext)} bytes")
            print(f"Expected structure: 12(nonce) + {len(data)}(ciphertext) + 16(tag) = {12 + len(data) + 16}")

        else:
            # GCM DECRYPTION
            ciphertext = read_file(input_file)

            print(f"DEBUG: Input file length: {len(ciphertext)} bytes")

            if len(ciphertext) < 12 + 16:  # nonce + tag
                print(f"Error: Input file too short for GCM", file=sys.stderr)
                print(f"       Got {len(ciphertext)} bytes, need at least {12 + 16}", file=sys.stderr)
                sys.exit(1)

            if iv is not None:
                # Use provided nonce
                if len(iv) != 12:
                    print(f"Error: Nonce must be 12 bytes for GCM", file=sys.stderr)
                    sys.exit(1)
                nonce = iv
                data_to_decrypt = ciphertext
                print(f"DEBUG: Using provided nonce: {nonce.hex()}")
                print(f"DEBUG: Data to decrypt length: {len(data_to_decrypt)} bytes")

                gcm = GCM(key, nonce)
            else:
                # Extract nonce from file (first 12 bytes)
                nonce = ciphertext[:12]
                data_to_decrypt = ciphertext  # remaining data
                print(f"DEBUG: Extracted nonce from file: {nonce.hex()}")
                print(f"DEBUG: Data to decrypt (without nonce) length: {len(data_to_decrypt)} bytes")

                gcm = GCM(key, nonce)

            # Decrypt with authentication check
            try:
                plaintext = gcm.decrypt(data_to_decrypt, aad)

                # Write decrypted data
                write_file(output_file, plaintext)

                print(f"Success: GCM decryption completed. Authenticity verified.")
                if aad:
                    print(f"AAD verified (hex): {aad.hex()}")

            except AuthenticationError as e:
                print(f"Error: Authentication failed - {e}", file=sys.stderr)
                if os.path.exists(output_file):
                    os.remove(output_file)
                sys.exit(1)
            except Exception as e:
                print(f"Error during GCM decryption: {e}", file=sys.stderr)
                if os.path.exists(output_file):
                    os.remove(output_file)
                sys.exit(1)

    except AuthenticationError as e:
        print(f"Error: Authentication failed - {e}", file=sys.stderr)
        if os.path.exists(output_file):
            os.remove(output_file)
        sys.exit(1)
    except ImportError as e:
        print(f"Error: GCM module not available", file=sys.stderr)
        print(f"Make sure gcm.py is in cryptocore/modes/ directory", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error in GCM mode: {e}", file=sys.stderr)
        if os.path.exists(output_file):
            os.remove(output_file)
        sys.exit(1)


def handle_etm_mode(encrypt, key, input_file, output_file, aad, mac_key):
    """Handle Encrypt-then-MAC mode"""
    try:
        from src.aead_handler import AEADHandler

        if encrypt:
            # Encrypt-then-MAC ENCRYPTION
            data = read_file(input_file)

            # Encrypt with Encrypt-then-MAC
            ciphertext = AEADHandler.encrypt_then_mac(
                data, key, mac_key, aad, 'ctr'
            )

            # Write result
            write_file(output_file, ciphertext)

            print(f"Success: Encrypt-then-MAC completed. Data written to {output_file}")
            print(f"Encryption key (hex): {key.hex()}")
            print(f"MAC key (hex): {mac_key.hex()}")
            if aad:
                print(f"AAD used (hex): {aad.hex()}")

        else:
            # Encrypt-then-MAC DECRYPTION
            ciphertext = read_file(input_file)

            # Decrypt with MAC verification
            plaintext = AEADHandler.decrypt_and_verify(
                ciphertext, key, mac_key, aad, 'ctr'
            )

            if plaintext is None:
                print(f"Error: Authentication failed - MAC verification error",
                      file=sys.stderr)
                if os.path.exists(output_file):
                    os.remove(output_file)
                sys.exit(1)

            # Write decrypted data
            write_file(output_file, plaintext)

            print(f"Success: Decryption and MAC verification completed")
            print(f"Data authenticity verified")

    except ImportError as e:
        print(f"Error: AEAD module not available", file=sys.stderr)
        print(f"Make sure aead_handler.py is in cryptocore/ directory", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error in ETM mode: {e}", file=sys.stderr)
        if os.path.exists(output_file):
            os.remove(output_file)
        sys.exit(1)


def handle_derive(args):
    """Handle the derive command"""
    validate_derive_args(args)

    try:
        password = args.password
        if args.password_file:
            try:
                with open(args.password_file, 'r') as f:
                    password = f.read().strip()
            except IOError as e:
                print(f"Error reading password file: {e}", file=sys.stderr)
                return 1

        if args.salt:
            salt_hex = args.salt
            if salt_hex.startswith('0x') or salt_hex.startswith('0X'):
                salt_hex = salt_hex[2:]
            salt = bytes.fromhex(salt_hex)
        else:
            salt = generate_random_bytes(16)
            salt_hex = salt.hex()

        from src.kdf.pbkdf2 import pbkdf2_hmac_sha256

        derived_key = pbkdf2_hmac_sha256(
            password=password,
            salt=salt,
            iterations=args.iterations,
            dklen=args.length
        )

        key_hex = derived_key.hex()

        if not args.no_print:
            print(f"{key_hex} {salt_hex}")

        if args.output:
            try:
                with open(args.output, 'wb') as f:
                    f.write(derived_key)
                if not args.no_print:
                    print(f"Key also written to: {args.output}")
            except IOError as e:
                print(f"Error writing output file: {e}", file=sys.stderr)
                return 1

        return 0

    except ImportError as e:
        print(f"Error: KDF module not available: {e}", file=sys.stderr)
        print("Make sure kdf/pbkdf2.py is in the cryptocore directory", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error during key derivation: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    args = parse_args()

    if args.command == "encrypt":
        # ENCRYPTION/DECRYPTION LOGIC
        key = validate_key(args.key, args.encrypt)
        aad = validate_aad(args.aad)
        iv = validate_iv(args.iv, args.mode, args.encrypt)

        mac_key = None
        if args.mode == "etm":
            if not args.mac_key:
                print(f"Error: --mac-key is required for Encrypt-then-MAC mode", file=sys.stderr)
                sys.exit(1)

            try:
                mac_key_hex = args.mac_key
                if mac_key_hex.startswith('0x') or mac_key_hex.startswith('0X'):
                    mac_key_hex = mac_key_hex[2:]
                mac_key = bytes.fromhex(mac_key_hex)
            except ValueError:
                print(f"Error: Invalid MAC key format", file=sys.stderr)
                sys.exit(1)

        if not os.path.exists(args.input):
            print(f"Error: Input file '{args.input}' does not exist", file=sys.stderr)
            sys.exit(1)

        output_file = args.output
        if not output_file:
            if args.encrypt:
                if args.mode == "gcm":
                    output_file = args.input + ".gcm"
                elif args.mode == "etm":
                    output_file = args.input + ".etm"
                else:
                    output_file = args.input + ".enc"
            else:
                base = args.input
                for ext in ['.enc', '.gcm', '.etm']:
                    if base.endswith(ext):
                        base = base[:-len(ext)]
                        break
                output_file = base + ".dec"

        try:
            # Handle GCM mode
            if args.mode == "gcm":
                handle_gcm_mode(
                    args.encrypt,
                    key,
                    args.input,
                    output_file,
                    aad,
                    iv
                )

            # Handle Encrypt-then-MAC mode
            elif args.mode == "etm":
                if not mac_key:
                    print(f"Error: MAC key is required for Encrypt-then-MAC mode", file=sys.stderr)
                    sys.exit(1)

                handle_etm_mode(
                    args.encrypt,
                    key,
                    args.input,
                    output_file,
                    aad,
                    mac_key
                )

            else:
                # LEGACY LOGIC FOR OTHER MODES
                mode_class = get_mode_class(args.mode)

                if args.encrypt:
                    # ENCRYPTION
                    cipher = mode_class(key)

                    data = read_file(args.input)

                    if args.mode == "ecb":
                        result = cipher.encrypt(data)
                        iv_used = b""

                        write_file(output_file, result)
                    else:
                        result, iv_used = cipher.encrypt(data)

                        write_file_with_iv(output_file, iv_used, result)

                    print(f"Success: Encrypted data written to {output_file}")
                    if args.mode != "ecb":
                        print(f"IV used (hex): {iv_used.hex()}")

                    if not args.key:
                        print(f"Note: Save the generated key for decryption")

                else:
                    # DECRYPTION
                    cipher = mode_class(key)

                    if args.mode == "ecb":
                        data = read_file(args.input)
                        result = cipher.decrypt(data)
                    else:
                        data, iv_used = read_file_with_iv_or_none(args.input, iv)

                        if args.mode in ["ecb", "cbc"] and len(data) == 0:
                            print(f"Error: Input file is empty or contains only IV", file=sys.stderr)
                            print(f"       For {args.mode.upper()} mode, file must contain ciphertext data",
                                  file=sys.stderr)
                            sys.exit(1)

                        result = cipher.decrypt(data, iv_used)

                    write_file(output_file, result)

                    print(f"Success: Decrypted data written to {output_file}")

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "dgst":
        # HASHING AND HMAC LOGIC
        if not os.path.exists(args.input):
            print(f"Error: Input file '{args.input}' does not exist", file=sys.stderr)
            sys.exit(1)

        if args.hmac:
            if not args.key:
                print("Error: --key is required when using --hmac", file=sys.stderr)
                sys.exit(1)

            try:
                key_hex = args.key
                if key_hex.startswith('0x') or key_hex.startswith('0X'):
                    key_hex = key_hex[2:]

                bytes.fromhex(key_hex)
            except ValueError:
                print(f"Error: Invalid HMAC key format", file=sys.stderr)
                print(f"       Key must be a hexadecimal string", file=sys.stderr)
                print(f"       Example: 00112233445566778899aabbccddeeff", file=sys.stderr)
                sys.exit(1)

        if args.verify and not args.hmac:
            print("Error: --verify can only be used with --hmac", file=sys.stderr)
            sys.exit(1)

        if args.verify and args.output:
            print("Error: --verify and --output cannot be used together", file=sys.stderr)
            print("       Use either --verify to check HMAC or --output to save HMAC", file=sys.stderr)
            sys.exit(1)

        try:
            if args.verify:
                from src.hash_handler import verify_hmac
                success = verify_hmac(
                    args.algorithm,
                    args.input,
                    args.key,
                    args.verify
                )

                sys.exit(0 if success else 1)
            else:
                from src.hash_handler import compute_hash
                compute_hash(
                    args.algorithm,
                    args.input,
                    args.output,
                    args.key if args.hmac else None
                )

        except ImportError as e:
            print(f"Error: Hash/HMAC functionality not available: {e}", file=sys.stderr)
            print("Make sure hash and HMAC modules are installed", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error computing hash/HMAC: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "derive":
        # KEY DERIVATION LOGIC
        validate_derive_args(args)

        try:
            password = args.password
            if args.password_file:
                try:
                    with open(args.password_file, 'r') as f:
                        password = f.read().strip()
                except IOError as e:
                    print(f"Error reading password file: {e}", file=sys.stderr)
                    sys.exit(1)

            if args.salt:
                salt_hex = args.salt
                if salt_hex.startswith('0x') or salt_hex.startswith('0X'):
                    salt_hex = salt_hex[2:]
                salt = bytes.fromhex(salt_hex)
            else:
                salt = generate_random_bytes(16)
                salt_hex = salt.hex()

            from src.kdf.pbkdf2 import pbkdf2_hmac_sha256

            derived_key = pbkdf2_hmac_sha256(
                password=password,
                salt=salt,
                iterations=args.iterations,
                dklen=args.length
            )

            key_hex = derived_key.hex()

            if not args.no_print:
                print(f"{key_hex} {salt_hex}")

            if args.output:
                try:
                    with open(args.output, 'wb') as f:
                        f.write(derived_key)
                    if not args.no_print:
                        print(f"Key also written to: {args.output}")
                except IOError as e:
                    print(f"Error writing output file: {e}", file=sys.stderr)
                    sys.exit(1)

        except ImportError as e:
            print(f"Error: KDF module not available: {e}", file=sys.stderr)
            print("Make sure kdf/pbkdf2.py is in the cryptocore directory", file=sys.stderr)
            sys.exit(1)
        except ValueError as e:
            print(f"Error: Invalid parameter: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error during key derivation: {e}", file=sys.stderr)
            sys.exit(1)

    else:
        print(f"Error: Unknown command '{args.command}'", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

