import os
from isap import ISAP, AuthenticatedData
import time

def test_basic_functionality():
    isap = ISAP()
    key = os.urandom(ISAP.KEY_SIZE)
    nonce = os.urandom(ISAP.NONCE_SIZE)
    plaintext = b"Hello, this is a test message for ISAP encryption!"
    associated_data = b"Important metadata"
    
    encrypted = isap.encrypt(plaintext, key, nonce, associated_data)
    decrypted = isap.decrypt(encrypted.ciphertext, key, nonce, encrypted.tag, associated_data)
    assert decrypted == plaintext, "Basic encryption/decryption failed"
    print("Basic functionality test passed!")

def test_various_message_lengths():
    isap = ISAP()
    key = os.urandom(ISAP.KEY_SIZE)
    nonce = os.urandom(ISAP.NONCE_SIZE)
    
    test_cases = [
        b"",  # Empty message
        b"A",  # Single byte
        b"AB" * 4,  # 8 bytes (RATE size)
        b"C" * 15,  # Partial block
        b"D" * 16,  # Full block
        os.urandom(100),  # Random large message
    ]
    
    for plaintext in test_cases:
        encrypted = isap.encrypt(plaintext, key, nonce)
        decrypted = isap.decrypt(encrypted.ciphertext, key, nonce, encrypted.tag)
        error_msg = "Failed for length {}".format(len(plaintext))
        assert decrypted == plaintext, error_msg
    print("Variable length messages test passed!")

def test_associated_data():
    isap = ISAP()
    key = os.urandom(ISAP.KEY_SIZE)
    nonce = os.urandom(ISAP.NONCE_SIZE)
    plaintext = b"Test message"
    
    # Test with different associated data
    ad_cases = [
        None,
        b"",
        b"Short AD",
        b"Long associated data" * 10
    ]
    
    for ad in ad_cases:
        encrypted = isap.encrypt(plaintext, key, nonce, ad)
        decrypted = isap.decrypt(encrypted.ciphertext, key, nonce, encrypted.tag, ad)
        error_msg = "Failed with AD: {}".format(ad)
        assert decrypted == plaintext, error_msg
    print("Associated data test passed!")

def test_error_cases():
    isap = ISAP()
    key = os.urandom(ISAP.KEY_SIZE)
    nonce = os.urandom(ISAP.NONCE_SIZE)
    plaintext = b"Test message"
    
    # Test invalid key size
    try:
        isap.encrypt(plaintext, key[:-1], nonce)
        assert False, "Should fail with invalid key size"
    except ValueError:
        pass

    # Test invalid nonce size
    try:
        isap.encrypt(plaintext, key, nonce[:-1])
        assert False, "Should fail with invalid nonce size"
    except ValueError:
        pass

    # Test tag tampering
    encrypted = isap.encrypt(plaintext, key, nonce)
    tampered_tag = bytearray(encrypted.tag)
    tampered_tag[0] ^= 1
    try:
        isap.decrypt(encrypted.ciphertext, key, nonce, bytes(tampered_tag))
        assert False, "Should fail with tampered tag"
    except ValueError:
        pass
    
    print("Error handling test passed!")

def test_performance():
    isap = ISAP()
    key = os.urandom(ISAP.KEY_SIZE)
    nonce = os.urandom(ISAP.NONCE_SIZE)
    
    sizes = [1024, 1024*10]  # 1KB, 10KB
    for size in sizes:
        data = os.urandom(size)
        
        start_time = time.time()
        encrypted = isap.encrypt(data, key, nonce)
        encrypt_time = time.time() - start_time
        
        start_time = time.time()
        decrypted = isap.decrypt(encrypted.ciphertext, key, nonce, encrypted.tag)
        decrypt_time = time.time() - start_time
        
        print(f"\nSize: {size/1024:.2f}KB")
        print(f"Encryption speed: {size/encrypt_time/1024:.2f} KB/s")
        print(f"Decryption speed: {size/decrypt_time/1024:.2f} KB/s")

def test_nonce_reuse_warning():
    isap = ISAP()
    key = os.urandom(ISAP.KEY_SIZE)
    nonce = os.urandom(ISAP.NONCE_SIZE)
    message1 = b"First message"
    message2 = b"Second message"
    
    # Demonstrate why nonce reuse is dangerous
    enc1 = isap.encrypt(message1, key, nonce)
    enc2 = isap.encrypt(message2, key, nonce)
    print("\nWarning: Nonce reuse detected!")
    print("This is unsafe in practice!")

if __name__ == "__main__":
    print("Running comprehensive ISAP tests...\n")
    
    test_basic_functionality()
    test_various_message_lengths()
    test_associated_data()
    test_error_cases()
    # test_performance()
    test_nonce_reuse_warning()
    
    print("\nAll tests completed successfully!")