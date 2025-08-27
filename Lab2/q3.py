from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import time

def des_encrypt_decrypt():
    pt = "Performance Testing of Encryption Algorithms"
    k = "0123456789ABCDEF"  
    key = bytes.fromhex(k)

    print("\n" + "="*60)
    print("DES ENCRYPTION/DECRYPTION")
    print("="*60)
    print(f"Plaintext: {pt}")
    print(f"Key (hex): {k}")
    print(f"Key length: {len(key)} bytes ({len(key)*8} bits)")


    cipher_enc = DES.new(key, DES.MODE_ECB)
    padded_message = pad(pt.encode(), DES.block_size)
    
    start_time = time.time()
    ct = cipher_enc.encrypt(padded_message)
    enc_time = time.time() - start_time
    
    print(f"Ciphertext (hex): {ct.hex()}")
    print(f"Encryption time: {enc_time:.6f} seconds")


    cipher_dec = DES.new(key, DES.MODE_ECB)
    
    start_time = time.time()
    decrypted_padded = cipher_dec.decrypt(ct)
    mes = unpad(decrypted_padded, DES.block_size).decode()
    dec_time = time.time() - start_time
    
    print(f"Decrypted message: {mes}")
    print(f"Decryption time: {dec_time:.6f} seconds")
    print(f"Original == Decrypted: {pt == mes}")

    return enc_time, dec_time

def aes_256_encrypt_decrypt():
    pt = "Performance Testing of Encryption Algorithms"
    k = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
    key = bytes.fromhex(k)

    print("\n" + "="*60)
    print("AES-256 ENCRYPTION/DECRYPTION")
    print("="*60)
    print(f"Plaintext: {pt}")
    print(f"Key (hex): {k}")
    print(f"Key length: {len(key)} bytes ({len(key)*8} bits)")


    cipher_enc = AES.new(key, AES.MODE_ECB)
    padded_message = pad(pt.encode(), AES.block_size)
    
    start_time = time.time()
    ct = cipher_enc.encrypt(padded_message)
    enc_time = time.time() - start_time
    
    print(f"Ciphertext (hex): {ct.hex()}")
    print(f"Encryption time: {enc_time:.6f} seconds")


    cipher_dec = AES.new(key, AES.MODE_ECB)
    
    start_time = time.time()
    decrypted_padded = cipher_dec.decrypt(ct)
    mes = unpad(decrypted_padded, AES.block_size).decode()
    dec_time = time.time() - start_time
    
    print(f"Decrypted message: {mes}")
    print(f"Decryption time: {dec_time:.6f} seconds")
    print(f"Original == Decrypted: {pt == mes}")

    return enc_time, dec_time

print("COMPARING ENCRYPTION ALGORITHM PERFORMANCE")
print("Message: 'Performance Testing of Encryption Algorithms'")

des_enc, des_dec = des_encrypt_decrypt()
aes_enc, aes_dec = aes_256_encrypt_decrypt()

print("\n" + "="*60)
print("PERFORMANCE COMPARISON")
print("="*60)
print(f"DES Encryption Time:    {des_enc:.6f} seconds")
print(f"AES-256 Encryption Time: {aes_enc:.6f} seconds")
print(f"DES Decryption Time:    {des_dec:.6f} seconds")
print(f"AES-256 Decryption Time: {aes_dec:.6f} seconds")

enc_ratio = des_enc / aes_enc if aes_enc > 0 else 0
dec_ratio = des_dec / aes_dec if aes_dec > 0 else 0

print(f"\nDES is {enc_ratio:.2f}x {'slower' if enc_ratio > 1 else 'faster'} than AES-256 for encryption")
print(f"DES is {dec_ratio:.2f}x {'slower' if dec_ratio > 1 else 'faster'} than AES-256 for decryption")