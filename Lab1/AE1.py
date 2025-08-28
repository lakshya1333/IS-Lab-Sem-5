import string

ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

alphabet = string.ascii_uppercase

def decrypt(cipher, shift):
    result = ""
    for ch in cipher:
        if ch in alphabet:
            idx = alphabet.index(ch)
            result += alphabet[(idx - shift) % 26]
        else:
            result += ch
    return result

for key in range(26):
    plaintext = decrypt(ciphertext, key)
    tag = " <--- close to birthday" if abs(key - 13) <= 3 else ""
    print(f"Key {key:2d}: {plaintext}{tag}")
