import struct
import hmac
from typing import List, Optional
from dataclasses import dataclass
from crypto_base import AuthenticatedData, CryptoError, rotate_left, xor_bytes
@dataclass
class AuthenticatedData:
    ciphertext: bytes
    tag: bytes

class Elephant:
    def __init__(self):
        self.ROUNDS = 12
        self.STATE_SIZE = 25  # 5x5 state
        self.round_constants = [
            0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
            0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
            0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
            0x0000000000000088, 0x0000000080008009, 0x000000008000000A
        ]
        self.log_file = "elephant_debug.log"
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        """XOR two byte strings"""
        return bytes(x ^ y for x, y in zip(a, b))
    def log(self, message: str) -> None:
        with open(self.log_file, "a") as f:
            f.write(message + "\n")
    def initialize_state(self) -> List[int]:
        """Initialize empty state"""
        return [0] * self.STATE_SIZE

    def bytes_to_state(self, data: bytes) -> List[int]:
        """Convert bytes to state array"""
        state = self.initialize_state()
        for i in range(0, min(len(data), 16), 8):
            if i + 8 <= len(data):
                state[i//8] = struct.unpack(">Q", data[i:i+8])[0]
            else:
                padded = data[i:] + b'\x00' * (8 - len(data[i:]))
                state[i//8] = struct.unpack(">Q", padded)[0]
        return state

    def permutation(self, state: List[int]) -> None:
        """Apply Elephant permutation to the state"""
        for round_idx in range(self.ROUNDS):
            # θ (theta) step
            C = [0] * 5
            for x in range(5):
                C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            
            D = [0] * 5
            for x in range(5):
                D[x] = C[(x - 1) % 5] ^ rotate_left(C[(x + 1) % 5], 1)

            for x in range(5):
                for y in range(5):
                    state[x + 5 * y] ^= D[x]
            temp = state[1]
            positions = [
                (0, 1), (1, 1), (2, 1), (3, 1), (4, 1),
                (0, 2), (1, 2), (2, 2), (3, 2), (4, 2),
                (0, 3), (1, 3), (2, 3), (3, 3), (4, 3),
                (0, 4), (1, 4), (2, 4), (3, 4), (4, 4)
            ]
            
            for x, y in positions:
                offset = ((x + 3 * y) % 5, x)
                next_pos = offset[0] + 5 * offset[1]
                new_temp = state[next_pos]
                state[next_pos] = rotate_left(temp, (x + y * 2) % 64)
                temp = new_temp
            for y in range(5):
                start = 5 * y
                t = state[start:start + 5].copy()
                for x in range(5):
                    state[start + x] = t[x] ^ ((~t[(x + 1) % 5]) & t[(x + 2) % 5])
            state[0] ^= self.round_constants[round_idx]

    def process_associated_data(self, state: List[int], associated_data: bytes) -> None:
        """Process associated data into state"""
        if associated_data:
            state_copy = state.copy()
            for i in range(0, len(associated_data), 8):
                block = associated_data[i:i + 8].ljust(8, b'\x00')
                state[0] ^= struct.unpack(">Q", block)[0]
                self.permutation(state)
            # XOR the original state after processing AD
            for i in range(len(state)):
                state[i] ^= state_copy[i]

    def encrypt(self, plaintext: bytes, key: bytes, nonce: bytes,
               associated_data: Optional[bytes] = None) -> AuthenticatedData:
        """Encrypt data and generate authentication tag"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(nonce) != 8:
            raise ValueError("Nonce must be 8 bytes")
        # Initialize state with key and nonce
        state = self.bytes_to_state(key + nonce)
        self.permutation(state)
        # Process associated data
        if associated_data:
            self.process_associated_data(state, associated_data)
        # Initialize tag computation state
        tag_state = state.copy()
        
        # Encrypt plaintext
        self.log("encrypt first : state = " + str(state))
        ciphertext = bytearray()
        for i in range(0, len(plaintext), 8):
            original_len = len(plaintext[i:i + 8])
            is_last_block = (i + 8 >= len(plaintext))
            
            # Pad block with zeros
            block = plaintext[i:i + 8].ljust(8, b'\x00')
            block_val = struct.unpack(">Q", block)[0]
            
            keystream = state[0]
            encrypted_block = struct.pack(">Q", block_val ^ keystream)
            ciphertext.extend(encrypted_block[:original_len])
            
            # For the last block, make sure we use the same length as the original data
            if is_last_block:
                state_update_val = struct.unpack(">Q", plaintext[i:i + original_len].ljust(8, b'\x00'))[0]
                state[0] ^= state_update_val
                tag_state[0] ^= state_update_val
            else:
                state[0] ^= block_val
                tag_state[0] ^= block_val
                
            self.permutation(state)
            self.permutation(tag_state)
        self.log("encrypt : last tag_state = " + str(tag_state))
        tag = struct.pack(">Q", tag_state[0])
        return AuthenticatedData(bytes(ciphertext), tag)

    def decrypt(self, ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes,
               associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt data and verify authentication tag"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(nonce) != 8:
            raise ValueError("Nonce must be 8 bytes")
        if len(tag) != 8:
            raise ValueError("Tag must be 8 bytes")

        # Initialize state with key and nonce
        state = self.bytes_to_state(key + nonce)
        self.permutation(state)
        # Process associated data
        if associated_data:
            self.process_associated_data(state, associated_data)

        # Initialize tag computation state
        tag_state = state.copy()
        
        # Decrypt ciphertext
        self.log("decrppt first state  = " + str(state))
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 8):
            original_len = len(ciphertext[i:i + 8])
            is_last_block = (i + 8 >= len(ciphertext))
            
            # Pad block with zeros
            block = ciphertext[i:i + 8].ljust(8, b'\x00')
            block_val = struct.unpack(">Q", block)[0]
            
            keystream = state[0]
            decrypted_val = block_val ^ keystream
            decrypted_block = struct.pack(">Q", decrypted_val)
            plaintext.extend(decrypted_block[:original_len])
            
            # For the last block, same length should be used as the original data
            if is_last_block:
                state_update_val = struct.unpack(">Q", decrypted_block[:original_len].ljust(8, b'\x00'))[0]
                state[0] ^= state_update_val
                tag_state[0] ^= state_update_val
            else:
                state[0] ^= decrypted_val
                tag_state[0] ^= decrypted_val
                
            self.permutation(state)
            self.permutation(tag_state)
        self.log("decrypt : last tag_state = " + str(tag_state))
        # Verify tag
        computed_tag = struct.pack(">Q", tag_state[0])
        if not hmac.compare_digest(computed_tag, tag):
            raise ValueError("Authentication failed")
        
        return bytes(plaintext)
    
    def encrypt_cbc(self, plaintext: bytes, key: bytes, iv: bytes, 
                associated_data: Optional[bytes] = None) -> AuthenticatedData:
        """CBC mode encryption"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(iv) != 8:
            raise ValueError("IV must be 8 bytes")

        # Initialize states
        state = self.bytes_to_state(key + iv)
        self.permutation(state)
        
        if associated_data:
            self.process_associated_data(state, associated_data)
        
        tag_state = state.copy()
        ciphertext = bytearray()
        previous = iv

        # Process plaintext in blocks
        for i in range(0, len(plaintext), 8):
            original_len = len(plaintext[i:i + 8])
            is_last_block = (i + 8 >= len(plaintext))
            
            block = plaintext[i:i + 8].ljust(8, b'\x00')
            xored = xor_bytes(block, previous)
            
            block_val = struct.unpack(">Q", xored)[0]
            keystream = state[0]
            encrypted_val = block_val ^ keystream
            encrypted_block = struct.pack(">Q", encrypted_val)
            
            ciphertext.extend(encrypted_block[:original_len])
            previous = encrypted_block
            
            # Handle last block specially
            if is_last_block:
                state_update_val = struct.unpack(">Q", encrypted_block[:original_len].ljust(8, b'\x00'))[0]
                state[0] ^= state_update_val
                tag_state[0] ^= state_update_val
            else:
                state[0] ^= encrypted_val
                tag_state[0] ^= encrypted_val
            
            self.permutation(state)
            self.permutation(tag_state)

        tag = struct.pack(">Q", tag_state[0])
        return AuthenticatedData(bytes(ciphertext), tag)

    def decrypt_cbc(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes,
                    associated_data: Optional[bytes] = None) -> bytes:
        """CBC mode decryption"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(iv) != 8:
            raise ValueError("IV must be 8 bytes")
        if len(tag) != 8:
            raise ValueError("Tag must be 8 bytes")

        # Initialize states
        state = self.bytes_to_state(key + iv)
        self.permutation(state)
        
        if associated_data:
            self.process_associated_data(state, associated_data)
        
        tag_state = state.copy()
        plaintext = bytearray()
        previous = iv

        # Process ciphertext in blocks
        for i in range(0, len(ciphertext), 8):
            original_len = len(ciphertext[i:i + 8])
            is_last_block = (i + 8 >= len(ciphertext))
            
            block = ciphertext[i:i + 8].ljust(8, b'\x00')
            block_val = struct.unpack(">Q", block)[0]
            
            keystream = state[0]
            decrypted_val = block_val ^ keystream
            decrypted_block = struct.pack(">Q", decrypted_val)
            
            plaintext_block = xor_bytes(decrypted_block, previous)
            plaintext.extend(plaintext_block[:original_len])
            previous = block
            
            # Handle last block specially
            if is_last_block:
                state_update_val = struct.unpack(">Q", block[:original_len].ljust(8, b'\x00'))[0]
                state[0] ^= state_update_val
                tag_state[0] ^= state_update_val
            else:
                state[0] ^= block_val
                tag_state[0] ^= block_val
            
            self.permutation(state)
            self.permutation(tag_state)

        # Verify tag
        computed_tag = struct.pack(">Q", tag_state[0])
        if not hmac.compare_digest(computed_tag, tag):
            raise ValueError("Authentication failed")

        return bytes(plaintext)

    def encrypt_ofb(self, plaintext: bytes, key: bytes, iv: bytes,
                    associated_data: Optional[bytes] = None) -> AuthenticatedData:
        """OFB mode encryption"""
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes")
        if len(iv) != 8:
            raise ValueError("IV must be 8 bytes")

        blocks = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
        previous = iv
        ciphertext = bytearray()
        
        state = self.bytes_to_state(key + iv)
        self.permutation(state)
        tag_state = state.copy()

        for block in blocks:
            keystream = self.encrypt(previous, key, iv, associated_data).ciphertext
            encrypted = xor_bytes(block, keystream[:len(block)])
            ciphertext.extend(encrypted)
            previous = keystream
            
            tag_state[0] ^= struct.unpack(">Q", encrypted.ljust(8, b'\x00'))[0]
            self.permutation(tag_state)

        tag = struct.pack(">Q", tag_state[0])
        return AuthenticatedData(bytes(ciphertext), tag)

    def decrypt_ofb(self, ciphertext: bytes, key: bytes, iv: bytes, tag: bytes,
                    associated_data: Optional[bytes] = None) -> bytes:
        """OFB mode decryption"""
        # In OFB mode, decryption is the same as encryption
        return self.encrypt_ofb(ciphertext, key, iv, associated_data).ciphertext