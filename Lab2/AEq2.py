from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# DES key (must be 8 bytes)
key = bytes.fromhex("A1B2C3D4E5F60708")
block_size = 8  # DES block size = 64 bits

# Data blocks (hex to bytes)
block1 = bytes.fromhex("54686973206973206120636f6e666964656e7469616c206d657373616765")
block2 = bytes.fromhex("416e64207468697320697320746865207365636f6e6420626c6f636b")

# Create DES cipher (ECB mode for direct block encryption)
cipher = DES.new(key, DES.MODE_ECB)

# Encrypt with padding
ciphertext1 = cipher.encrypt(pad(block1, block_size))
ciphertext2 = cipher.encrypt(pad(block2, block_size))

print("Ciphertext Block1 (hex):", ciphertext1.hex())
print("Ciphertext Block2 (hex):", ciphertext2.hex())

# --- Decryption ---
decipher = DES.new(key, DES.MODE_ECB)
plaintext1 = unpad(decipher.decrypt(ciphertext1), block_size)
plaintext2 = unpad(decipher.decrypt(ciphertext2), block_size)

print("Decrypted Block1:", plaintext1.decode())
print("Decrypted Block2:", plaintext2.decode())
