import time
import matplotlib.pyplot as plt
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Five sample messages (different lengths)
messages = [
    b"Hello World!",
    b"Cryptography is fun.",
    b"Symmetric encryption test with DES and AES.",
    b"Data Security is crucial in modern communication.",
    b"Benchmarking encryption algorithms with Python!"
]

# Modes to test
modes = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC,
    "CFB": AES.MODE_CFB,
    "OFB": AES.MODE_OFB,
    "CTR": AES.MODE_CTR
}

results = {}

def benchmark_cipher(cipher_name, key_size=None):
    times = {}
    if cipher_name == "DES":
        key = get_random_bytes(8)  # DES requires 8-byte key
        for mode_name, mode in modes.items():
            if mode == AES.MODE_CTR:  # CTR uses nonce instead of IV
                cipher = DES.new(key, mode, nonce=b"0")
            elif mode == AES.MODE_ECB:
                cipher = DES.new(key, mode)
            else:
                iv = get_random_bytes(8)
                cipher = DES.new(key, mode, iv=iv)

            start = time.time()
            for msg in messages:
                padded_msg = pad(msg, 8)
                cipher.encrypt(padded_msg)
            times[mode_name] = time.time() - start

    else:  # AES
        key = get_random_bytes(key_size // 8)
        block_size = 16
        for mode_name, mode in modes.items():
            if mode == AES.MODE_CTR:
                cipher = AES.new(key, mode, nonce=b"0")
            elif mode == AES.MODE_ECB:
                cipher = AES.new(key, mode)
            else:
                iv = get_random_bytes(block_size)
                cipher = AES.new(key, mode, iv=iv)

            start = time.time()
            for msg in messages:
                padded_msg = pad(msg, block_size)
                cipher.encrypt(padded_msg)
            times[mode_name] = time.time() - start

    results[f"{cipher_name}-{key_size if key_size else ''}"] = times


# Run benchmarks
benchmark_cipher("DES")
benchmark_cipher("AES", 128)
benchmark_cipher("AES", 192)
benchmark_cipher("AES", 256)

# Plot results
for algo, times in results.items():
    plt.plot(list(times.keys()), list(times.values()), marker='o', label=algo)

plt.title("DES vs AES (128,192,256) Execution Time in Different Modes")
plt.xlabel("Modes of Operation")
plt.ylabel("Execution Time (seconds)")
plt.legend()
plt.grid(True)
plt.show()
