#!/usr/bin/env python3
"""
CLI Parser for CryptoCore
Handles command line arguments for all sprints (1-6)
"""

import argparse
import sys
from typing import Optional, List, Tuple


def parse_args(args: Optional[List[str]] = None):
    """
    Parse command line arguments for CryptoCore

    Args:
        args: List of command line arguments (defaults to sys.argv[1:])

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        prog='cryptocore',
        description='CryptoCore - A comprehensive cryptographic toolkit',
        epilog="""
Examples:
  # AES-GCM encryption with AAD
  cryptocore --algorithm aes --mode gcm --encrypt --key 001122... --input file.txt --output file.enc --aad aabbcc
  
  # AES-GCM decryption
  cryptocore --algorithm aes --mode gcm --decrypt --key 001122... --input file.enc --output file.txt --aad aabbcc
  
  # Hash computation
  cryptocore dgst --algorithm sha256 --input file.txt
  
  # HMAC computation
  cryptocore dgst --algorithm sha256 --hmac --key 001122... --input file.txt
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # ===== MAIN ENCRYPTION/DECRYPTION ARGUMENTS =====
    parser.add_argument(
        '--algorithm',
        choices=['aes'],
        default='aes',
        help='Encryption algorithm (default: aes)'
    )

    parser.add_argument(
        '--mode',
        choices=['ecb', 'cbc', 'cfb', 'ofb', 'ctr', 'gcm'],
        default='ecb',
        help='Mode of operation (default: ecb)'
    )

    # Operation type (encrypt/decrypt)
    operation_group = parser.add_mutually_exclusive_group(required=False)
    operation_group.add_argument(
        '--encrypt',
        action='store_true',
        help='Perform encryption'
    )
    operation_group.add_argument(
        '--decrypt',
        action='store_true',
        help='Perform decryption'
    )

    # Key and input/output
    parser.add_argument(
        '--key',
        help='Encryption key as hexadecimal string (optional for encryption)'
    )

    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Input file path (use "-" for stdin)'
    )

    parser.add_argument(
        '--output', '-o',
        help='Output file path (optional, uses stdout if not specified)'
    )

    # ===== GCM-SPECIFIC ARGUMENTS (SPRINT 6) =====
    gcm_group = parser.add_argument_group('GCM mode options')
    gcm_group.add_argument(
        '--aad',
        help='Additional Authenticated Data for GCM mode (hex string)'
    )

    # Nonce/IV handling
    iv_group = parser.add_argument_group('IV/Nonce options')
    iv_group.add_argument(
        '--iv',
        help='Initialization Vector for decryption (hex string). For GCM, use as nonce.'
    )
    iv_group.add_argument(
        '--nonce',
        help='Nonce for GCM mode (hex string). Overrides --iv if both specified.'
    )

    # ===== HASH/HMAC COMMAND (SPRINTS 4-5) =====
    parser.add_argument(
        'dgst',
        nargs='?',
        help='Compute message digest (hash)'
    )

    hash_group = parser.add_argument_group('Hash/HMAC options')
    hash_group.add_argument(
        '--hash-algorithm',
        choices=['sha256', 'sha3_256', 'blake2'],
        default='sha256',
        help='Hash algorithm for dgst command (default: sha256)'
    )

    hash_group.add_argument(
        '--hmac',
        action='store_true',
        help='Enable HMAC mode for dgst command'
    )

    hash_group.add_argument(
        '--verify',
        help='Verify HMAC against file'
    )

    # ===== OPTIONAL FLAGS =====
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress non-essential output'
    )

    # Parse arguments
    parsed_args = parser.parse_args(args)

    # Post-validation
    validate_args(parsed_args)

    return parsed_args


def validate_args(args):
    """
    Validate parsed arguments

    Args:
        args: Parsed arguments

    Raises:
        SystemExit: If arguments are invalid
    """
    # Check for dgst command
    if args.dgst is not None:
        # For dgst command, we don't need encrypt/decrypt flags
        if args.encrypt or args.decrypt:
            print("ERROR: Cannot use --encrypt/--decrypt with dgst command", file=sys.stderr)
            sys.exit(1)

        # HMAC requires key
        if args.hmac and not args.key:
            print("ERROR: --key is required when using --hmac", file=sys.stderr)
            sys.exit(1)

        # Verify requires HMAC
        if args.verify and not args.hmac:
            print("ERROR: --verify requires --hmac", file=sys.stderr)
            sys.exit(1)

        return  # Skip encryption/decryption validation

    # ===== VALIDATION FOR ENCRYPTION/DECRYPTION =====

    # Check operation type
    if not args.encrypt and not args.decrypt:
        print("ERROR: Either --encrypt or --decrypt must be specified", file=sys.stderr)
        sys.exit(1)

    # Check key for decryption
    if args.decrypt and not args.key and args.mode != 'gcm':
        print("ERROR: --key is required for decryption", file=sys.stderr)
        sys.exit(1)

    # ===== GCM-SPECIFIC VALIDATION =====
    if args.mode == 'gcm':
        # Validate AAD
        if args.aad:
            try:
                bytes.fromhex(args.aad)
            except ValueError:
                print(f"ERROR: Invalid AAD hex string: {args.aad}", file=sys.stderr)
                sys.exit(1)

        # Validate nonce/IV
        if args.nonce:
            try:
                nonce_bytes = bytes.fromhex(args.nonce)
                if len(nonce_bytes) != 12:
                    print(f"WARNING: GCM nonce is recommended to be 12 bytes, got {len(nonce_bytes)}",
                          file=sys.stderr)
            except ValueError:
                print(f"ERROR: Invalid nonce hex string: {args.nonce}", file=sys.stderr)
                sys.exit(1)

        if args.iv:
            try:
                bytes.fromhex(args.iv)
            except ValueError:
                print(f"ERROR: Invalid IV hex string: {args.iv}", file=sys.stderr)
                sys.exit(1)

        # Warn if nonce/IV provided during encryption
        if args.encrypt and (args.nonce or args.iv):
            print("WARNING: --nonce/--iv should not be provided during GCM encryption",
                  file=sys.stderr)

    # ===== GENERAL VALIDATION =====

    # Validate key
    if args.key:
        try:
            key_bytes = bytes.fromhex(args.key)
            if args.algorithm == 'aes':
                if len(key_bytes) not in [16, 24, 32]:
                    print(f"ERROR: AES key must be 16, 24, or 32 bytes, got {len(key_bytes)}",
                          file=sys.stderr)
                    sys.exit(1)
        except ValueError:
            print(f"ERROR: Invalid key hex string: {args.key}", file=sys.stderr)
            sys.exit(1)

    # Check input/output
    if args.input == args.output and args.input != '-':
        print("ERROR: Input and output cannot be the same file", file=sys.stderr)
        sys.exit(1)


def get_aad_bytes(args) -> bytes:
    """
    Get AAD bytes from arguments

    Args:
        args: Parsed arguments

    Returns:
        bytes: AAD bytes (empty if not specified)
    """
    if args.aad:
        return bytes.fromhex(args.aad)
    return b""


def get_nonce_bytes(args, from_data: bytes = None) -> Tuple[bytes, bytes]:
    """
    Get nonce bytes from arguments or data

    Args:
        args: Parsed arguments
        from_data: Data to extract nonce from (if not in args)

    Returns:
        tuple: (nonce_bytes, remaining_data)
    """
    # Priority: --nonce > --iv > from_data > None
    if args.nonce:
        nonce = bytes.fromhex(args.nonce)
        return nonce, from_data

    if args.iv:
        nonce = bytes.fromhex(args.iv)
        return nonce, from_data

    if from_data and len(from_data) >= 12:
        nonce = from_data[:12]
        remaining = from_data[12:]
        return nonce, remaining

    return None, from_data


def print_help():
    """Print help message"""
    parse_args(['--help'])


if __name__ == "__main__":
    # Test the parser
    args = parse_args()
    print("Parsed arguments:")
    for arg in vars(args):
        print(f"  {arg}: {getattr(args, arg)}")