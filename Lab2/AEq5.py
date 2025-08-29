from Crypto.Cipher import AES
from Crypto.Util import Counter

# Parameters
key = b"0123456789ABCDEF0123456789ABCDEF"   # 16-byte AES-128 key
nonce = b"0000000000000000"                 # 8-byte nonce
message = b"Cryptography Lab Exercise"

# Build counter object (AES CTR requires counter with nonce)
ctr = Counter.new(64, prefix=nonce, initial_value=0)

# --- Encryption ---
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
ciphertext = cipher.encrypt(message)
print("Ciphertext (hex):", ciphertext.hex())

# --- Decryption (reset counter) ---
ctr_dec = Counter.new(64, prefix=nonce, initial_value=0)
decipher = AES.new(key, AES.MODE_CTR, counter=ctr_dec)
plaintext = decipher.decrypt(ciphertext)
print("Decrypted message:", plaintext.decode())
