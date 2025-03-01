# test_integrity.py
import os
from file_integrity import FileIntegrity

def test_document_integrity_elephant():
    print("\n=== Testing with Elephant Algorithm ===")
    # Create test document
    test_file = "test_document_elephant.txt"
    with open(test_file, "w") as f:
        f.write("This is a confidential document.\nDo not modify!")
    
    # Generate key (16 bytes) and nonce (8 bytes for Elephant)
    user_key = os.urandom(16)
    nonce = os.urandom(8)  # Elephant needs 8 bytes
    
    print("Initial setup:")
    print(f"User key (hex): {user_key.hex()}")
    print(f"Nonce (hex): {nonce.hex()}")
    print(f"Nonce length: {len(nonce)} bytes")
    
    try:
        # Test with original file
        print("\nTesting original file...")
        extract = FileIntegrity.generate_file_extract(test_file, user_key, nonce, 'Elephant')
        FileIntegrity.append_extract_to_file(test_file, extract)
        is_valid = FileIntegrity.verify_file_integrity(test_file, user_key, nonce, 'Elephant')
        print(f"Original file integrity: {'VALID' if is_valid else 'INVALID'}")
        
        # Test with modified file
        print("\nModifying file and testing again...")
        with open(test_file, "r+") as f:
            content = f.read()
            f.seek(0)
            f.write(content.replace("confidential", "modified"))
            f.truncate()
        
        is_valid = FileIntegrity.verify_file_integrity(test_file, user_key, nonce, 'Elephant')
        print(f"Modified file integrity: {'VALID' if is_valid else 'INVALID'}")
    
    except Exception as e:
        print(f"Error occurred: {str(e)}")
    
    finally:
        # Clean up test file
        if os.path.exists(test_file):
            os.remove(test_file)
            print("\nTest file cleaned up")

def test_document_integrity_isap():
    print("\n=== Testing with ISAP Algorithm ===")
    # Create test document
    test_file = "test_document_isap.txt"
    with open(test_file, "w") as f:
        f.write("This is a confidential document.\nDo not modify!")
    
    # Generate key (16 bytes) and nonce (16 bytes for ISAP)
    user_key = os.urandom(16)
    nonce = os.urandom(16)  # ISAP needs 16 bytes
    
    print("Initial setup:")
    print(f"User key (hex): {user_key.hex()}")
    print(f"Nonce (hex): {nonce.hex()}")
    print(f"Nonce length: {len(nonce)} bytes")
    
    try:
        # Test with original file
        print("\nTesting original file...")
        extract = FileIntegrity.generate_file_extract(test_file, user_key, nonce, 'ISAP')
        FileIntegrity.append_extract_to_file(test_file, extract)
        is_valid = FileIntegrity.verify_file_integrity(test_file, user_key, nonce, 'ISAP')
        print(f"Original file integrity: {'VALID' if is_valid else 'INVALID'}")
        
        # Test with modified file
        print("\nModifying file and testing again...")
        with open(test_file, "r+") as f:
            content = f.read()
            f.seek(0)
            f.write(content.replace("confidential", "modified"))
            f.truncate()
        
        is_valid = FileIntegrity.verify_file_integrity(test_file, user_key, nonce, 'ISAP')
        print(f"Modified file integrity: {'VALID' if is_valid else 'INVALID'}")
    
    except Exception as e:
        print(f"Error occurred: {str(e)}")
    
    finally:
        # Clean up test file
        if os.path.exists(test_file):
            os.remove(test_file)
            print("\nTest file cleaned up")

if __name__ == "__main__":
    print("Running file integrity tests...")
    test_document_integrity_elephant()
    test_document_integrity_isap()
    print("\nAll tests completed!")