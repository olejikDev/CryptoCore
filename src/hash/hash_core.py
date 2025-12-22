"""
РћСЃРЅРѕРІРЅРѕР№ РєР»Р°СЃСЃ РґР»СЏ СЂР°Р±РѕС‚С‹ СЃ С…РµС€-С„СѓРЅРєС†РёСЏРјРё
Sprint 4: РЈРїСЂР°РІР»РµРЅРёРµ СЂР°Р·Р»РёС‡РЅС‹РјРё Р°Р»РіРѕСЂРёС‚РјР°РјРё С…РµС€РёСЂРѕРІР°РЅРёСЏ
"""

import os
from .sha256 import SHA256
from .sha3_256 import SHA3_256


class HashCore:
    """РћСЃРЅРѕРІРЅРѕР№ РєР»Р°СЃСЃ РґР»СЏ СЂР°Р±РѕС‚С‹ СЃ С…РµС€-С„СѓРЅРєС†РёСЏРјРё"""

    SUPPORTED_ALGORITHMS = {
        'sha256': SHA256,
        'sha3-256': SHA3_256,
    }

    def __init__(self, algorithm='sha256'):
        """РРЅРёС†РёР°Р»РёР·Р°С†РёСЏ С…РµС€-Р°Р»РіРѕСЂРёС‚РјР°"""
        algorithm = algorithm.lower()

        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"РќРµРїРѕРґРґРµСЂР¶РёРІР°РµРјС‹Р№ Р°Р»РіРѕСЂРёС‚Рј: {algorithm}. "
                             f"РџРѕРґРґРµСЂР¶РёРІР°РµС‚СЃСЏ: {', '.join(self.SUPPORTED_ALGORITHMS.keys())}")

        self.algorithm_name = algorithm
        self.hasher = self.SUPPORTED_ALGORITHMS[algorithm]()

    def hash_data(self, data):
        """РҐРµС€РёСЂРѕРІР°РЅРёРµ РґР°РЅРЅС‹С…"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        self.hasher.update(data)
        return self.hasher.hexdigest()

    def hash_file(self, filepath, chunk_size=8192):
        """
        РҐРµС€РёСЂРѕРІР°РЅРёРµ С„Р°Р№Р»Р° С‡Р°РЅРєР°РјРё

        Args:
            filepath: РїСѓС‚СЊ Рє С„Р°Р№Р»Сѓ
            chunk_size: СЂР°Р·РјРµСЂ С‡Р°РЅРєР° РІ Р±Р°Р№С‚Р°С…

        Returns:
            str: hex С…РµС€ С„Р°Р№Р»Р°
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Р¤Р°Р№Р» РЅРµ РЅР°Р№РґРµРЅ: {filepath}")

        if not os.path.isfile(filepath):
            raise ValueError(f"'{filepath}' РЅРµ СЏРІР»СЏРµС‚СЃСЏ С„Р°Р№Р»РѕРј")

        return self.hasher.hash_file(filepath, chunk_size)

    def hash_file_incremental(self, filepath, chunk_size=8192):
        """
        РРЅРєСЂРµРјРµРЅС‚Р°Р»СЊРЅРѕРµ С…РµС€РёСЂРѕРІР°РЅРёРµ С„Р°Р№Р»Р° (РіРµРЅРµСЂР°С‚РѕСЂ)
        РџРѕР»РµР·РЅРѕ РґР»СЏ РїСЂРѕРіСЂРµСЃСЃ-Р±Р°СЂРѕРІ
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Р¤Р°Р№Р» РЅРµ РЅР°Р№РґРµРЅ: {filepath}")

        file_size = os.path.getsize(filepath)
        bytes_processed = 0

        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                self.hasher.update(chunk)
                bytes_processed += len(chunk)

                # Р’РѕР·РІСЂР°С‰Р°РµРј РїСЂРѕРіСЂРµСЃСЃ
                yield bytes_processed / file_size if file_size > 0 else 1.0

        return self.hasher.hexdigest()

