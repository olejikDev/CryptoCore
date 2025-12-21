#!/usr/bin/env python3
"""
File I/O operations for CryptoCore
Handles reading/writing files with proper error handling
"""

import os
import sys
from typing import Optional, Generator, Tuple, BinaryIO


class FileIOError(Exception):
    """Exception for file I/O errors"""
    pass


class FileHandler:
    """Handler for file operations"""

    @staticmethod
    def read_file(filepath: str, binary: bool = True) -> bytes:
        """
        Read entire file

        Args:
            filepath: Path to file
            binary: Read in binary mode

        Returns:
            File contents as bytes

        Raises:
            FileIOError: If file cannot be read
        """
        if filepath == '-':
            # Read from stdin
            try:
                if binary:
                    return sys.stdin.buffer.read()
                else:
                    return sys.stdin.read().encode('utf-8')
            except Exception as e:
                raise FileIOError(f"Cannot read from stdin: {e}")

        mode = 'rb' if binary else 'r'
        try:
            with open(filepath, mode) as f:
                return f.read()
        except FileNotFoundError:
            raise FileIOError(f"File not found: {filepath}")
        except PermissionError:
            raise FileIOError(f"Permission denied: {filepath}")
        except IOError as e:
            raise FileIOError(f"Cannot read file {filepath}: {e}")

    @staticmethod
    def write_file(filepath: str, data: bytes, binary: bool = True) -> None:
        """
        Write data to file

        Args:
            filepath: Path to file
            data: Data to write
            binary: Write in binary mode

        Raises:
            FileIOError: If file cannot be written
        """
        if filepath is None or filepath == '-':
            # Write to stdout
            try:
                if binary:
                    sys.stdout.buffer.write(data)
                else:
                    sys.stdout.write(data.decode('utf-8'))
                sys.stdout.flush()
            except Exception as e:
                raise FileIOError(f"Cannot write to stdout: {e}")
            return

        mode = 'wb' if binary else 'w'
        try:
            # Create directory if needed
            os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)

            with open(filepath, mode) as f:
                f.write(data)
        except PermissionError:
            raise FileIOError(f"Permission denied: {filepath}")
        except IOError as e:
            raise FileIOError(f"Cannot write file {filepath}: {e}")

    @staticmethod
    def read_chunks(filepath: str, chunk_size: int = 8192) -> Generator[bytes, None, None]:
        """
        Read file in chunks

        Args:
            filepath: Path to file
            chunk_size: Size of each chunk

        Yields:
            Chunks of file data
        """
        if filepath == '-':
            # Read stdin in chunks
            while True:
                chunk = sys.stdin.buffer.read(chunk_size)
                if not chunk:
                    break
                yield chunk
            return

        try:
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
        except FileNotFoundError:
            raise FileIOError(f"File not found: {filepath}")
        except IOError as e:
            raise FileIOError(f"Cannot read file {filepath}: {e}")

    @staticmethod
    def write_chunks(filepath: str, chunks: Generator[bytes, None, None]) -> None:
        """
        Write chunks to file

        Args:
            filepath: Path to file
            chunks: Generator yielding chunks of data
        """
        if filepath is None or filepath == '-':
            # Write to stdout
            for chunk in chunks:
                sys.stdout.buffer.write(chunk)
            sys.stdout.flush()
            return

        try:
            with open(filepath, 'wb') as f:
                for chunk in chunks:
                    f.write(chunk)
        except IOError as e:
            raise FileIOError(f"Cannot write file {filepath}: {e}")

    @staticmethod
    def get_file_size(filepath: str) -> int:
        """
        Get file size in bytes

        Args:
            filepath: Path to file

        Returns:
            File size in bytes
        """
        if filepath == '-':
            # Can't get stdin size
            return 0

        try:
            return os.path.getsize(filepath)
        except OSError:
            return 0

    @staticmethod
    def file_exists(filepath: str) -> bool:
        """
        Check if file exists

        Args:
            filepath: Path to file

        Returns:
            True if file exists
        """
        if filepath == '-':
            return True  # stdin always "exists"

        return os.path.exists(filepath)

    # ===== GCM-SPECIFIC METHODS =====

    @staticmethod
    def write_gcm_output(filepath: str, nonce: bytes, ciphertext: bytes, tag: bytes) -> None:
        """
        Write GCM output (nonce + ciphertext + tag)

        Args:
            filepath: Output file path
            nonce: 12-byte nonce
            ciphertext: Encrypted data
            tag: 16-byte authentication tag
        """
        if len(nonce) != 12:
            raise ValueError(f"GCM nonce must be 12 bytes, got {len(nonce)}")
        if len(tag) != 16:
            raise ValueError(f"GCM tag must be 16 bytes, got {len(tag)}")

        data = nonce + ciphertext + tag
        FileHandler.write_file(filepath, data)

    @staticmethod
    def read_gcm_input(filepath: str, nonce: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """
        Read GCM input and extract components

        Args:
            filepath: Input file path
            nonce: Optional nonce (if provided, not read from file)

        Returns:
            tuple: (nonce, ciphertext, tag)

        Raises:
            ValueError: If file is too short or format invalid
        """
        data = FileHandler.read_file(filepath)

        if nonce is not None:
            # Nonce provided externally
            ciphertext_and_tag = data
        else:
            # Read nonce from file
            if len(data) < 12:
                raise ValueError(f"File too short for GCM nonce: {len(data)} bytes")
            nonce = data[:12]
            ciphertext_and_tag = data[12:]

        # Extract tag (last 16 bytes)
        if len(ciphertext_and_tag) < 16:
            raise ValueError(f"File too short for GCM tag: {len(ciphertext_and_tag)} bytes")

        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]

        return nonce, ciphertext, tag

    @staticmethod
    def safe_write_with_backup(filepath: str, data: bytes, backup_ext: str = '.bak') -> None:
        """
        Safely write data with backup

        Args:
            filepath: Target file path
            data: Data to write
            backup_ext: Backup file extension
        """
        if not filepath or filepath == '-':
            FileHandler.write_file(filepath, data)
            return

        # Create backup if file exists
        backup_file = None
        if os.path.exists(filepath):
            backup_file = filepath + backup_ext
            try:
                os.replace(filepath, backup_file)
            except OSError as e:
                raise FileIOError(f"Cannot create backup: {e}")

        # Write new data
        try:
            FileHandler.write_file(filepath, data)
        except Exception as e:
            # Restore backup on error
            if backup_file and os.path.exists(backup_file):
                try:
                    os.replace(backup_file, filepath)
                except OSError:
                    pass  # Can't restore, but we tried
            raise e

        # Remove backup on success
        if backup_file and os.path.exists(backup_file):
            try:
                os.remove(backup_file)
            except OSError:
                pass  # Ignore cleanup errors

    @staticmethod
    def cleanup_on_failure(filepath: str) -> None:
        """
        Clean up file on operation failure

        Args:
            filepath: File to clean up
        """
        if filepath and filepath != '-' and os.path.exists(filepath):
            try:
                os.remove(filepath)
            except OSError:
                pass  # Ignore cleanup errors

    # ===== HELPER METHODS =====

    @staticmethod
    def format_size(size_bytes: int) -> str:
        """
        Format file size in human-readable format

        Args:
            size_bytes: Size in bytes

        Returns:
            Formatted size string
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"

    @staticmethod
    def get_default_output_name(input_file: str, operation: str, mode: str = None) -> str:
        """
        Generate default output filename

        Args:
            input_file: Input filename
            operation: 'encrypt', 'decrypt', or 'hash'
            mode: Encryption mode (for extensions)

        Returns:
            Default output filename
        """
        if input_file == '-':
            return '-'  # Use stdout

        base, ext = os.path.splitext(input_file)

        if operation == 'encrypt':
            if mode == 'gcm':
                return f"{base}.gcm"
            else:
                return f"{base}.enc"
        elif operation == 'decrypt':
            if ext in ['.enc', '.gcm']:
                return f"{base}.dec"
            else:
                return f"{base}.decrypted"
        elif operation == 'hash':
            return f"{base}.hash"
        else:
            return f"{base}.out"


def read_file_safe(filepath: str) -> bytes:
    """
    Safe wrapper for reading files with error messages

    Args:
        filepath: Path to file

    Returns:
        File contents

    Raises:
        SystemExit: On error with message
    """
    try:
        return FileHandler.read_file(filepath)
    except FileIOError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


def write_file_safe(filepath: str, data: bytes) -> None:
    """
    Safe wrapper for writing files with error messages

    Args:
        filepath: Path to file
        data: Data to write

    Raises:
        SystemExit: On error with message
    """
    try:
        FileHandler.write_file(filepath, data)
    except FileIOError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    # Test the file handler
    import tempfile

    # Test basic operations
    test_data = b"Hello, CryptoCore!"

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_name = tmp.name
        FileHandler.write_file(tmp_name, test_data)

        read_back = FileHandler.read_file(tmp_name)
        assert read_back == test_data
        print(f"✓ Basic read/write test passed")

        # Test chunks
        chunks = list(FileHandler.read_chunks(tmp_name, chunk_size=5))
        reassembled = b''.join(chunks)
        assert reassembled == test_data
        print(f"✓ Chunked read test passed")

    os.unlink(tmp_name)
    print("All tests passed!")