from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# AES-256 Key (must be 32 bytes)
key = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
message = b"Encryption Strength"
block_size = 16  # AES block size = 128 bits

# AES-256 in ECB mode (for demo)
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt with padding
ciphertext = cipher.encrypt(pad(message, block_size))
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt
decipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(decipher.decrypt(ciphertext), block_size)
print("Decrypted message:", plaintext.decode())
