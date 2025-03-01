# test_modes.py
import os
from elephant import Elephant
from isap import ISAP

def test_cbc_mode():
    print("\nTesting CBC mode...")
    
    # Initialize cipher
    elephant = Elephant()
    
    # Test case 1: Simple message
    key = os.urandom(16)
    iv = os.urandom(8)
    plaintext = b"This is a test message for CBC mode!"
    
    print("Test case 1:")
    print("Plaintext:", plaintext)
    print("Plaintext length:", len(plaintext))
    
    try:
        # Encrypt
        print("\nEncrypting...")
        encrypted = elephant.encrypt_cbc(plaintext, key, iv)
        print("Ciphertext length:", len(encrypted.ciphertext))
        
        # Decrypt
        print("\nDecrypting...")
        decrypted = elephant.decrypt_cbc(encrypted.ciphertext, key, iv, encrypted.tag)
        print("Decrypted:", decrypted)
        print("Decrypted length:", len(decrypted))
        
        assert decrypted == plaintext
        print("Test case 1 passed!")
        
    except Exception as e:
        print(f"Test failed: {str(e)}")
        raise

    # Test case 2: Different message sizes
    test_cases = [
        b"",                # Empty
        b"A",              # Single byte
        b"12345678",       # Exactly one block
        b"123456789",      # More than one block
        b"A" * 16,         # Multiple blocks
    ]
    
    print("\nTesting different message sizes:")
    for test_case in test_cases:
        try:
            encrypted = elephant.encrypt_cbc(test_case, key, iv)
            decrypted = elephant.decrypt_cbc(encrypted.ciphertext, key, iv, encrypted.tag)
            assert decrypted == test_case
            print(f"Length {len(test_case)} bytes: OK")
        except Exception as e:
            print(f"Failed for length {len(test_case)}: {str(e)}")
            raise

# if __name__ == "__main__":
#     test_cbc_mode()

def test_ofb_mode():
    print("\nTesting OFB mode...")
    
    # Test Elephant OFB
    print("\nTesting Elephant OFB:")
    elephant = Elephant()
    key = os.urandom(16)
    elephant_iv = os.urandom(8)  # Elephant uses 8-byte IV
    plaintext = b"This is a test message for OFB mode!"
    
    try:
        # Elephant test
        encrypted = elephant.encrypt_ofb(plaintext, key, elephant_iv)
        decrypted = elephant.decrypt_ofb(encrypted.ciphertext, key, elephant_iv, encrypted.tag)
        assert decrypted == plaintext
        print("Elephant basic OFB test passed!")
    except Exception as e:
        print(f"Elephant OFB test failed: {str(e)}")
        raise

    # Test ISAP OFB
    print("\nTesting ISAP OFB:")
    isap = ISAP()
    isap_iv = os.urandom(16)  # ISAP uses 16-byte IV/nonce
    
    try:
        # ISAP test
        encrypted = isap.encrypt_ofb(plaintext, key, isap_iv)
        decrypted = isap.decrypt_ofb(encrypted.ciphertext, key, isap_iv, encrypted.tag)
        assert decrypted == plaintext
        print("ISAP basic OFB test passed!")
    except Exception as e:
        print(f"ISAP OFB test failed: {str(e)}")
        raise

    # Test various message sizes
    test_cases = [
        b"",                # Empty
        b"A",              # Single byte
        b"12345678",       # One block
        b"123456789",      # More than one block
        b"A" * 16,         # Multiple blocks
    ]
    
    print("\nTesting different message sizes:")
    
    # Test Elephant with different sizes
    print("Elephant:")
    for test_case in test_cases:
        try:
            encrypted = elephant.encrypt_ofb(test_case, key, elephant_iv)
            decrypted = elephant.decrypt_ofb(encrypted.ciphertext, key, elephant_iv, encrypted.tag)
            assert decrypted == test_case
            print(f"Length {len(test_case)} bytes: OK")
        except Exception as e:
            print(f"Failed for length {len(test_case)}: {str(e)}")
            raise

    # Test ISAP with different sizes
    print("\nISAP:")
    for test_case in test_cases:
        try:
            encrypted = isap.encrypt_ofb(test_case, key, isap_iv)
            decrypted = isap.decrypt_ofb(encrypted.ciphertext, key, isap_iv, encrypted.tag)
            assert decrypted == test_case
            print(f"Length {len(test_case)} bytes: OK")
        except Exception as e:
            print(f"Failed for length {len(test_case)}: {str(e)}")
            raise

if __name__ == "__main__":
    print("Testing CBC and OFB modes...")
    test_cbc_mode()
    test_ofb_mode()
    print("\nAll mode tests passed!")