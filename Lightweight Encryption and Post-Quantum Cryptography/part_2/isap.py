from crypto_base import AuthenticatedData, rotate_left, bytes_to_state, state_to_bytes, xor_bytes
from typing import Optional, List
import os
import hmac
import struct
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings"""
    return bytes(x ^ y for x, y in zip(a, b))
class ISAP:
    KEY_SIZE = 16       # 128 bits
    NONCE_SIZE = 16     # 128 bits
    TAG_SIZE = 16       # 128 bits
    RATE = 8           # 64 bits
    STATE_SIZE = 40     # 320 bits
    PA_ROUNDS = 12      # Permutation-A rounds
    PB_ROUNDS = 6       # Permutation-B rounds

    def __init__(self):
        # Ascon round constants
        self.round_constants = [
            0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5,
            0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
        ]

    def permutation(self, state, rounds):
        """Apply Ascon permutation to the state"""
        for round_idx in range(rounds):
            # Add round constant
            state[2] ^= self.round_constants[round_idx]

            # Substitution layer (s-box)
            t = [0] * 5
            t[0] = state[0] ^ state[4]
            t[1] = state[1] ^ state[0]
            t[2] = state[2] ^ state[1]
            t[3] = state[3] ^ state[2]
            t[4] = state[4] ^ state[3]

            for i in range(5):
                state[i] ^= t[(i + 1) % 5]

            # Linear diffusion layer
            state[0] = rotate_left(state[0], 19) ^ rotate_left(state[0], 28)
            state[1] = rotate_left(state[1], 61) ^ rotate_left(state[1], 39)
            state[2] = rotate_left(state[2],  1) ^ rotate_left(state[2],  6)
            state[3] = rotate_left(state[3], 10) ^ rotate_left(state[3], 17)
            state[4] = rotate_left(state[4],  7) ^ rotate_left(state[4], 41)

    def initialize(self, key, nonce):
        """Initialize ISAP state with key and nonce"""
        state = bytes_to_state(key + nonce)
        self.permutation(state, self.PA_ROUNDS)
        return state

    def absorb(self, state, data, domain):
        """Absorb data into the state"""
        for i in range(0, len(data), self.RATE):
            block = data[i:i + self.RATE]
            state_bytes = state_to_bytes(state)
            for j, b in enumerate(block):
                state_bytes = state_bytes[:j] + bytes([b ^ state_bytes[j]]) + state_bytes[j+1:]
            state[:] = bytes_to_state(state_bytes)
            
            if i + self.RATE >= len(data):  # Last block
                state_bytes = state_to_bytes(state)
                state_bytes = state_bytes[:-1] + bytes([state_bytes[-1] ^ domain])
                state[:] = bytes_to_state(state_bytes)
            
            self.permutation(state, self.PB_ROUNDS)

    def squeeze(self, state, output_len):
        """Squeeze output from the state"""
        output = bytearray()
        while len(output) < output_len:
            output.extend(state_to_bytes(state)[:min(self.RATE, output_len - len(output))])
            if len(output) < output_len:
                self.permutation(state, self.PB_ROUNDS)
        return bytes(output)

    def encrypt(self, plaintext, key, nonce,
               associated_data = None):
        """Encrypt data and generate authentication tag"""
        if len(key) != self.KEY_SIZE:
            raise ValueError("Key must be {} bytes".format(self.KEY_SIZE))
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("Nonce must be {} bytes".format(self.NONCE_SIZE))


        # Initialize state
        state = self.initialize(key, nonce)

        # Process associated data
        if associated_data:
            self.absorb(state, associated_data, 0x01)

        # Encrypt plaintext
        ciphertext = bytearray()
        for i in range(0, len(plaintext), self.RATE):
            block = plaintext[i:i + self.RATE]
            keystream = self.squeeze(state, len(block))
            ciphertext.extend(xor_bytes(block, keystream))

        # Generate tag
        tag_state = self.initialize(key, nonce + bytes([0x02]))  # Domain separation
        self.absorb(tag_state, ciphertext, 0x03)
        tag = self.squeeze(tag_state, self.TAG_SIZE)

        return AuthenticatedData(bytes(ciphertext), tag)

    def decrypt(self, ciphertext, key, nonce, tag,
               associated_data = None):
        """Decrypt data and verify authentication tag"""
        if len(key) != self.KEY_SIZE:
            raise ValueError("Key must be {} bytes".format(self.KEY_SIZE))
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("Nonce must be {} bytes".format(self.NONCE_SIZE))
        if len(tag) != self.TAG_SIZE:
            raise ValueError("Tag must be {} bytes".format(self.TAG_SIZE))

        # Verify tag first (decrypt-then-verify)
        tag_state = self.initialize(key, nonce + bytes([0x02]))
        self.absorb(tag_state, ciphertext, 0x03)
        computed_tag = self.squeeze(tag_state, self.TAG_SIZE)

        if not hmac.compare_digest(computed_tag, tag):
            raise ValueError("Authentication failed")

        # Initialize state for decryption
        state = self.initialize(key, nonce)

        # Process associated data if present
        if associated_data:
            self.absorb(state, associated_data, 0x01)

        # Decrypt ciphertext
        plaintext = bytearray()
        for i in range(0, len(ciphertext), self.RATE):
            block = ciphertext[i:i + self.RATE]
            keystream = self.squeeze(state, len(block))
            plaintext.extend(xor_bytes(block, keystream))

        return bytes(plaintext)
    def encrypt_cbc(self, plaintext: bytes, key: bytes, iv: bytes,
                   associated_data: Optional[bytes] = None) -> AuthenticatedData:
        """CBC mode encryption"""
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")
        if len(iv) != self.NONCE_SIZE:
            raise ValueError(f"IV must be {self.NONCE_SIZE} bytes")

        blocks = [plaintext[i:i+self.RATE] for i in range(0, len(plaintext), self.RATE)]
        previous = iv
        ciphertext = bytearray()
        
        state = self.initialize(key, iv)
        tag_state = state.copy()

        for block in blocks:
            block = block.ljust(self.RATE, b'\x00')
            xored = xor_bytes(block, previous)
            encrypted = self.encrypt(xored, key, iv, associated_data).ciphertext
            ciphertext.extend(encrypted)
            previous = encrypted
            
            self.absorb(tag_state, encrypted, 0x03)

        tag = self.squeeze(tag_state, self.TAG_SIZE)
        return AuthenticatedData(bytes(ciphertext), tag)

    def decrypt_cbc(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes,
                   associated_data: Optional[bytes] = None) -> bytes:
        """CBC mode decryption"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(iv) != 8:
            raise ValueError("IV must be 8 bytes")

        blocks = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]
        previous = iv
        plaintext = bytearray()

        for block in blocks:
            decrypted = self.decrypt(block, key, iv, tag, associated_data)
            plaintext_block = xor_bytes(decrypted, previous)
            plaintext.extend(plaintext_block)
            previous = block

        return bytes(plaintext)

    def encrypt_ofb(self, plaintext: bytes, key: bytes, iv: bytes,
                associated_data: Optional[bytes] = None) -> AuthenticatedData:
        """OFB mode encryption"""
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")
        if len(iv) != self.NONCE_SIZE:
            raise ValueError(f"IV must be {self.NONCE_SIZE} bytes")

        blocks = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
        previous = iv
        ciphertext = bytearray()
        
        state = bytes_to_state(key + iv)
        self.permutation(state, self.PA_ROUNDS)
        tag_state = state.copy()

        for block in blocks:
            keystream = self.encrypt(previous, key, iv, associated_data).ciphertext
            encrypted = xor_bytes(block, keystream[:len(block)])
            ciphertext.extend(encrypted)
            previous = keystream
            
            tag_state[0] ^= struct.unpack(">Q", encrypted.ljust(8, b'\x00'))[0]
            self.permutation(tag_state, self.PB_ROUNDS)

        tag = self.squeeze(tag_state, self.TAG_SIZE)
        return AuthenticatedData(bytes(ciphertext), tag)

    def decrypt_ofb(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes,
                    associated_data: Optional[bytes] = None) -> bytes:
        """OFB mode decryption"""
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be {self.KEY_SIZE} bytes")
        if len(iv) != self.NONCE_SIZE:
            raise ValueError(f"IV must be {self.NONCE_SIZE} bytes")
        if len(tag) != self.TAG_SIZE:
            raise ValueError(f"Tag must be {self.TAG_SIZE} bytes")

        blocks = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]
        previous = iv
        plaintext = bytearray()
        
        state = bytes_to_state(key + iv)
        self.permutation(state, self.PA_ROUNDS)
        tag_state = state.copy()

        for block in blocks:
            keystream = self.encrypt(previous, key, iv, associated_data).ciphertext
            decrypted = xor_bytes(block, keystream[:len(block)])
            plaintext.extend(decrypted)
            previous = keystream
            
            tag_state[0] ^= struct.unpack(">Q", block.ljust(8, b'\x00'))[0]
            self.permutation(tag_state, self.PB_ROUNDS)

        # Verify tag
        computed_tag = self.squeeze(tag_state, self.TAG_SIZE)
        if not hmac.compare_digest(computed_tag, tag):
            raise ValueError("Authentication failed")

        return bytes(plaintext)
