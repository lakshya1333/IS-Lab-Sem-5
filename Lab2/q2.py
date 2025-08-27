from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

def aes_encrypt_decrypt_demo():

    message = "Sensitive Information"
    key_hex = "0123456789ABCDEF0123456789ABCDEF"
    

    key = bytes.fromhex(key_hex)
    
    print("Original Message:", message)
    print("Key (hex):", key_hex)
    print("Key length:", len(key), "bytes")
    print()
    

    cipher = AES.new(key, AES.MODE_ECB)  
    

    plaintext_bytes = message.encode('utf-8')
    padded_plaintext = pad(plaintext_bytes, AES.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_plaintext)
    ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')
    
    print("=== ENCRYPTION ===")
    print("Plaintext (bytes):", plaintext_bytes)
    print("Padded plaintext (bytes):", padded_plaintext)
    print("Ciphertext (hex):", ciphertext_hex)
    print()
    
    # Decryption
    cipher = AES.new(key, AES.MODE_ECB) 
    
    decrypted_padded = cipher.decrypt(ciphertext)
    
    decrypted_bytes = unpad(decrypted_padded, AES.block_size)
    decrypted_message = decrypted_bytes.decode('utf-8')
    
    print("=== DECRYPTION ===")
    print("Decrypted bytes:", decrypted_bytes)
    print("Decrypted message:", decrypted_message)
    print()
    

    print("=== VERIFICATION ===")
    if decrypted_message == message:
        print("✓ SUCCESS: Original message matches decrypted message!")
    else:
        print("✗ FAILED: Messages don't match!")
    
    return ciphertext_hex, decrypted_message

ciphertext, decrypted = aes_encrypt_decrypt_demo()