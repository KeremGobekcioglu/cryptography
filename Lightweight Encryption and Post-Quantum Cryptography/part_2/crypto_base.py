# crypto_base.py
# from dataclasses import dataclass
from typing import List, Optional, Tuple
import os
import struct

# crypto_base.py
class AuthenticatedData:
    def __init__(self, ciphertext, tag):
        self.ciphertext = ciphertext
        self.tag = tag

class CryptoError(Exception):
    """Base class for cryptographic exceptions"""
    pass

def rotate_left(value, shift, size=64):
    """Rotate left (circular left shift)"""
    return ((value << shift) | (value >> (size - shift))) & ((1 << size) - 1)

def bytes_to_state(data):
    """Convert bytes to state array of 64-bit integers"""
    return list(struct.unpack(">5Q", data.ljust(40, b'\x00')))

def state_to_bytes(state):
    """Convert state array of 64-bit integers to bytes"""
    return struct.pack(">5Q", *state)

def xor_bytes(a, b):
    """XOR two byte strings"""
    return bytes(x ^ y for x, y in zip(a, b))