from elephant import Elephant
import os

cipher = Elephant()
def test_elephant():
    # Initialize cipher
    
    # Generate random test data
    key = os.urandom(16)  # 16 bytes key
    nonce = os.urandom(8)  # 8 bytes nonce
    plaintext = b"Hello, this is a test message!"
    associated_data = b"Additional data"
    
    print("Original plaintext:", plaintext)
    print("Associated data:", associated_data)
    print("Key (hex):", key.hex())
    print("Nonce (hex):", nonce.hex())
    
    # Encrypt
    encrypted = cipher.encrypt(plaintext, key, nonce, associated_data)
    print("\nCiphertext (hex):", encrypted.ciphertext.hex())
    print("Tag (hex):", encrypted.tag.hex())
    
    # Decrypt
    decrypted = cipher.decrypt(encrypted.ciphertext, key, nonce, encrypted.tag, associated_data)
    print("\nDecrypted text:", decrypted)
    
    # Verify
    assert decrypted == plaintext
    
    test_cases = [
    b"",  # Empty message
    b"A" * 8,  # Exactly one block
    b"B" * 15,  # Partial block
    b"C" * 16,  # Multiple blocks
    os.urandom(1000),  # Large random message
]
    
    for plaintext in test_cases:
        key = os.urandom(16)
        nonce = os.urandom(8)
        associated_data = os.urandom(16)
        
        # Test with and without associated data
        for ad in [None, associated_data]:
            encrypted = cipher.encrypt(plaintext, key, nonce, ad)
            decrypted = cipher.decrypt(encrypted.ciphertext, key, nonce, encrypted.tag, ad)
            assert decrypted == plaintext, f"Failed for length {len(plaintext)}"
    
    print("\nEncryption/decryption test passed!")

def test_file_integrity():
    cipher = Elephant()
    key = os.urandom(16)  # 16 bytes key
    nonce = os.urandom(8)  # 8 bytes nonce
    
    # Create a test file
    test_file = "test_file.txt"
    with open(test_file, "wb") as f:
        f.write(b"This is a test file content.")
    
    # Read file and calculate hash
    with open(test_file, "rb") as f:
        file_content = f.read()
    
    # Encrypt the file content
    encrypted = cipher.encrypt(file_content, key, nonce)
    
    # Save encrypted content and tag
    with open(test_file + ".encrypted", "wb") as f:
        f.write(encrypted.ciphertext)
    with open(test_file + ".tag", "wb") as f:
        f.write(encrypted.tag)
    
    print(f"\nFile encryption completed:")
    print(f"Original size: {len(file_content)} bytes")
    print(f"Encrypted size: {len(encrypted.ciphertext)} bytes")
    print(f"Tag size: {len(encrypted.tag)} bytes")
    
    # Later, verify and decrypt
    with open(test_file + ".encrypted", "rb") as f:
        encrypted_content = f.read()
    with open(test_file + ".tag", "rb") as f:
        tag = f.read()
    
    # Decrypt and verify
    decrypted = cipher.decrypt(encrypted_content, key, nonce, tag)
    assert decrypted == file_content
    print("\nFile integrity test passed!")

def test_error_cases():
    # Test invalid inputs
    key = os.urandom(16)
    nonce = os.urandom(8)
    plaintext = b"Test message"
    
    try:
        # Wrong key size
        cipher.encrypt(plaintext, os.urandom(15), nonce)
        assert False, "Should fail with wrong key size"
    except ValueError:
        pass

    try:
        # Wrong nonce size
        cipher.encrypt(plaintext, key, os.urandom(7))
        assert False, "Should fail with wrong nonce size"
    except ValueError:
        pass

def test_tag_verification():
    # Test tag tampering
    key = os.urandom(16)
    nonce = os.urandom(8)
    plaintext = b"Test message"
    
    encrypted = cipher.encrypt(plaintext, key, nonce)
    tampered_tag = bytearray(encrypted.tag)
    tampered_tag[0] ^= 1  # Flip one bit
    
    try:
        cipher.decrypt(encrypted.ciphertext, key, nonce, bytes(tampered_tag))
        assert False, "Should fail with tampered tag"
    except ValueError:
        pass

if __name__ == "__main__":
    print("Running comprehensive Elephant cipher tests...\n")
    test_elephant()
    test_error_cases()
    test_tag_verification()
    test_file_integrity()
    print("\nAll tests passed!")