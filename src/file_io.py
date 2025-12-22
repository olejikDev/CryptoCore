"""
File I/O operations with IV handling
"""
import os
import sys
from typing import Optional, Tuple


def read_file_safe(filepath: str) -> bytes:
    """Read file safely"""
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}", file=sys.stderr)
        sys.exit(1)


def write_file_safe(filepath: str, data: bytes) -> None:
    """Write file safely"""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(data)
    except Exception as e:
        print(f"Error writing file {filepath}: {e}", file=sys.stderr)
        sys.exit(1)


class FileHandler:
    """РљР»Р°СЃСЃ РґР»СЏ СЂР°Р±РѕС‚С‹ СЃ С„Р°Р№Р»Р°РјРё"""

    @staticmethod
    def cleanup_on_failure(filepath: str) -> None:
        """РЈРґР°Р»РёС‚СЊ С„Р°Р№Р» РїСЂРё РЅРµСѓРґР°С‡РЅРѕР№ РѕРїРµСЂР°С†РёРё"""
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except:
            pass  # РРіРЅРѕСЂРёСЂСѓРµРј РѕС€РёР±РєРё РїСЂРё СѓРґР°Р»РµРЅРёРё


def read_file(filepath: str) -> bytes:
    """Read file safely (alias for read_file_safe)"""
    return read_file_safe(filepath)


def write_file(filepath: str, data: bytes) -> None:
    """Write file safely (alias for write_file_safe)"""
    write_file_safe(filepath, data)


def write_file_with_iv(filepath: str, iv: bytes, data: bytes) -> None:
    """Write file with IV prepended"""
    write_file_safe(filepath, iv + data)


def read_file_with_iv_or_none(filepath: str, iv: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """
    Read file, extracting IV if needed

    Args:
        filepath: Path to file
        iv: Optional IV (if provided, not read from file)

    Returns:
        Tuple of (data, iv)
    """
    data = read_file_safe(filepath)

    if iv is not None:
        # IV provided externally
        return data, iv
    else:
        # Read IV from file (first 16 bytes)
        if len(data) < 16:
            print(f"Error: File too short for IV extraction: {len(data)} bytes", file=sys.stderr)
            sys.exit(1)

        iv = data[:16]
        actual_data = data[16:]
        return actual_data, iv

