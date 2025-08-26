import string

def hill_encrypt(msg, K):
    msg = msg.replace(" ", "").upper()
    if len(msg) % 2 == 1:
        msg += "X"

    alphabet = {ch:i for i,ch in enumerate(string.ascii_uppercase)}
    rev = {i:ch for ch,i in alphabet.items()}

    ct = ""
    for i in range(0, len(msg), 2):
        p1, p2 = alphabet[msg[i]], alphabet[msg[i+1]]

        c1 = (K[0][0]*p1 + K[0][1]*p2) % 26
        c2 = (K[1][0]*p1 + K[1][1]*p2) % 26

        ct += rev[c1] + rev[c2]
    return ct


if __name__ == "__main__":
    K = [[3, 3], [2, 7]] 
    msg = "We live in an insecure world"

    ciphertext = hill_encrypt(msg, K)
    print("Plaintext :", msg)
    print("Ciphertext:", ciphertext)
