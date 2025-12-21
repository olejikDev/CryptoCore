"""Modes of operation package."""
from .ecb import ECBMode
from .cbc import CBCMode
from .cfb import CFBMode
from .ofb import OFBMode
from .ctr import CTRMode
from .gcm import GCM, AuthenticationError as GCMAuthenticationError


__all__ = ['ECBMode', 'CBCMode', 'CFBMode', 'OFBMode', 'CTRMode', 'GCM', 'GCMAuthenticationError']

MODES = {
    'ecb': ECBMode,
    'cbc': CBCMode,
    'cfb': CFBMode,
    'ofb': OFBMode,
    'ctr': CTRMode,
    'gcm': GCM
}