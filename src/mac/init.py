"""
РџР°РєРµС‚ РґР»СЏ СЂРµР°Р»РёР·Р°С†РёРё Message Authentication Codes (MAC)
Sprint 5: HMAC Рё AES-CMAC
"""

from .hmac import HMAC, compute_hmac
from .cmac import CMAC, compute_cmac

__all__ = ['HMAC', 'CMAC', 'compute_hmac', 'compute_cmac']

