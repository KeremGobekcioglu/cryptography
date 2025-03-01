# file_integrity.py
import os
import hashlib
import hmac
from isap import ISAP
from elephant import Elephant

class FileIntegrity:
    @staticmethod
    def generate_file_extract(filepath: str, key: bytes, nonce: bytes, algorithm: str) -> bytes:
        """Generate and encrypt file integrity extract using the specified algorithm."""
        with open(filepath, 'rb') as file:
            file_content = file.read()
        
        file_hash = hashlib.sha256(file_content).digest()
        
        if algorithm == 'ISAP':
            if len(nonce) != 16:
                raise ValueError("ISAP requires 16-byte nonce")
            isap = ISAP()
            authenticated_data = isap.encrypt(file_hash, key, nonce)
        elif algorithm == 'Elephant':
            if len(nonce) != 8:
                raise ValueError("Elephant requires 8-byte nonce")
            elephant = Elephant()
            authenticated_data = elephant.encrypt(file_hash, key, nonce)
        else:
            raise ValueError("Unsupported algorithm specified.")
        
        return authenticated_data.ciphertext + authenticated_data.tag

    @staticmethod
    def append_extract_to_file(filepath: str, extract: bytes) -> None:
        with open(filepath, 'ab') as file:
            file.write(extract)

    @staticmethod
    def verify_file_integrity(filepath: str, key: bytes, nonce: bytes, algorithm: str) -> bool:
        with open(filepath, 'rb') as file:
            file_content = file.read()
        
        encrypted_extract = file_content[-32:]
        file_data = file_content[:-32]
        
        if algorithm == 'ISAP':
            if len(nonce) != 16:
                raise ValueError("ISAP requires 16-byte nonce")
            isap = ISAP()
            ciphertext, tag = encrypted_extract[:16], encrypted_extract[16:]
            try:
                decrypted_hash = isap.decrypt(ciphertext, key, nonce, tag)
            except ValueError:
                return False
        elif algorithm == 'Elephant':
            if len(nonce) != 8:
                raise ValueError("Elephant requires 8-byte nonce")
            elephant = Elephant()
            ciphertext, tag = encrypted_extract[:16], encrypted_extract[16:]
            try:
                decrypted_hash = elephant.decrypt(ciphertext, key, nonce, tag)
            except ValueError:
                return False
        else:
            raise ValueError("Unsupported algorithm specified.")
        
        recalculated_hash = hashlib.sha256(file_data).digest()
        return hmac.compare_digest(decrypted_hash, recalculated_hash)