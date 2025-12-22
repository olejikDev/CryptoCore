import os
import hmac
import hashlib


class AuthenticationError(Exception):
    """сключение для ошибок аутентификации"""
    pass


class EncryptThenMAC:
    """Реализация паттерна Encrypt-then-MAC"""

    def __init__(self, enc_key, mac_key, cipher_mode='ctr', hash_algo='sha256'):
        """
        нициализация Encrypt-then-MAC

        Args:
            enc_key (bytes): Ключ для шифрования
            mac_key (bytes): Ключ для MAC
            cipher_mode (str): Режим шифрования ('ctr', 'cbc', etc.)
            hash_algo (str): Алгоритм хэширования для HMAC
        """
        self.enc_key = enc_key
        self.mac_key = mac_key
        self.cipher_mode = cipher_mode
        self.hash_algo = hash_algo

        # нициализация HMAC
        try:
            from src.mac.hmac import HMAC as CustomHMAC
            self.hmac = CustomHMAC(mac_key, hash_algo)
        except ImportError:
            # Fallback to built-in HMAC
            import hashlib
            self.hmac = hashlib

    def encrypt(self, plaintext, aad=b""):
        """
        Шифрование с последующим вычислением MAC

        Args:
            plaintext (bytes): Данные для шифрования
            aad (bytes): Ассоциированные данные

        Returns:
            bytes: IV/nonce + ciphertext + tag
        """
        if self.cipher_mode == 'ctr':
            from src.modes.ctr import CTRMode
            cipher = CTRMode(self.enc_key)

            # CTR.encrypt() возвращает iv + ciphertext
            iv_and_ciphertext = cipher.encrypt(plaintext)

            # Разделяем на iv и ciphertext
            iv = iv_and_ciphertext[:16]  # 8 байт nonce + 8 байт counter
            ciphertext = iv_and_ciphertext[16:]
        else:
            raise ValueError(f"Режим {self.cipher_mode} пока не поддерживается")

        # Вычисление MAC над ciphertext || aad
        mac_data = ciphertext + aad

        if hasattr(self.hmac, 'compute'):
            # Custom HMAC
            tag = self.hmac.compute(mac_data)
            tag_bytes = tag
        else:
            # Built-in HMAC
            hmac_obj = hmac.new(self.mac_key, mac_data, hashlib.sha256)
            tag_bytes = hmac_obj.digest()

        return iv + ciphertext + tag_bytes

    def decrypt(self, data, aad=b""):
        """
        Расшифрование с проверкой MAC

        Args:
            data (bytes): IV/nonce + ciphertext + tag
            aad (bytes): Ассоциированные данные

        Returns:
            bytes: Расшифрованный текст

        Raises:
            AuthenticationError: Если проверка MAC не удалась
        """
        if len(data) < 16 + 32:  # minimum: iv(16) + tag(32)
            raise AuthenticationError("Данные слишком короткие")

        # Разделение данных
        iv = data[:16]
        tag = data[-32:]  # SHA-256 дает 32-байтный хэш
        ciphertext = data[16:-32]

        # Проверка MAC
        mac_data = ciphertext + aad

        if hasattr(self.hmac, 'compute'):
            # Custom HMAC
            expected_tag = self.hmac.compute(mac_data)
            expected_tag_bytes = expected_tag
        else:
            # Built-in HMAC
            hmac_obj = hmac.new(self.mac_key, mac_data, hashlib.sha256)
            expected_tag_bytes = hmac_obj.digest()


        if not self._constant_time_compare(tag, expected_tag_bytes):
            raise AuthenticationError("Ошибка аутентификации: неверный MAC")

        # Расшифрование
        if self.cipher_mode == 'ctr':
            from src.modes.ctr import CTRMode
            cipher = CTRMode(self.enc_key, iv)

            # В CTR метод decrypt ожидает iv + ciphertext
            encrypted_data = iv + ciphertext
            plaintext = cipher.decrypt(encrypted_data)
        else:
            raise ValueError(f"Режим {self.cipher_mode} пока не поддерживается")

        return plaintext

    @staticmethod
    def _constant_time_compare(a, b):
        """Сравнение с постоянным временем"""
        if len(a) != len(b):
            return False

        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    @staticmethod
    def derive_keys(master_key, salt=b""):
        """
        Генерация отдельных ключей для шифрования и MAC из мастер-ключа

        Args:
            master_key (bytes): сходный ключ
            salt (bytes): Соль для KDF

        Returns:
            tuple: (enc_key, mac_key)
        """
        # Простой KDF на основе HKDF-подобной схемы
        hmac1 = hmac.new(master_key, b"encryption" + salt, hashlib.sha256).digest()
        hmac2 = hmac.new(master_key, b"authentication" + salt, hashlib.sha256).digest()

        # Берем первые 16 байт для AES-128
        enc_key = hmac1[:16]
        mac_key = hmac2

        return enc_key, mac_key


# Для обратной совместимости
__all__ = ['EncryptThenMAC', 'AuthenticationError']

