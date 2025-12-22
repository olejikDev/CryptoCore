"""
Пакет для реализации Message Authentication Codes (MAC)
Sprint 5: HMAC и AES-CMAC
"""

from .hmac import HMAC, compute_hmac
from .cmac import CMAC, compute_cmac

__all__ = ['HMAC', 'CMAC', 'compute_hmac', 'compute_cmac']

