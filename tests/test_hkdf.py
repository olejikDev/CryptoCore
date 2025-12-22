import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.kdf.hkdf import derive_key


class TestHKDF(unittest.TestCase):

    def test_deterministic(self):
        """Same inputs should produce same output"""
        master = b'0' * 32
        context = 'encryption'
        length = 32

        key1 = derive_key(master, context, length)
        key2 = derive_key(master, context, length)

        self.assertEqual(key1, key2)

    def test_context_separation(self):
        """Different contexts should produce different keys"""
        master = b'0' * 32
        length = 32

        key1 = derive_key(master, 'encryption', length)
        key2 = derive_key(master, 'authentication', length)

        self.assertNotEqual(key1, key2)

    def test_various_lengths(self):
        """Test various key lengths"""
        master = b'0' * 32
        context = 'test'

        for length in [1, 16, 32, 64, 128]:
            key = derive_key(master, context, length)
            self.assertEqual(len(key), length)

    def test_different_masters(self):
        """Different master keys should produce different keys"""
        master1 = b'0' * 32
        master2 = b'1' * 32
        context = 'same_context'
        length = 32

        key1 = derive_key(master1, context, length)
        key2 = derive_key(master2, context, length)

        self.assertNotEqual(key1, key2)


if __name__ == '__main__':
    unittest.main()