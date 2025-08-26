import string

class Playfair:
    def __init__(self, key):
        self.key = key.upper().replace("J", "I")
        self.matrix = self._generate_matrix()

    def _generate_matrix(self):
        seen = set()
        matrix = []

        for ch in self.key:
            if ch not in seen and ch in string.ascii_uppercase:
                seen.add(ch)
                matrix.append(ch)

        for ch in string.ascii_uppercase:
            if ch == "J":
                continue
            if ch not in seen:
                seen.add(ch)
                matrix.append(ch)

        return [matrix[i:i+5] for i in range(0, 25, 5)]

    def _pos(self, ch):
        for r in range(5):
            for c in range(5):
                if self.matrix[r][c] == ch:
                    return r, c
        return None

    def _prepare_text(self, text):
        text = text.upper().replace(" ", "").replace("J", "I")
        digraphs = []
        i = 0
        while i < len(text):
            a = text[i]
            b = ""
            if i+1 < len(text):
                b = text[i+1]
                if a == b:
                    b = "X"
                    i += 1
                else:
                    i += 2
            else:
                b = "X"
                i += 1
            digraphs.append(a+b)
        return digraphs

    def encrypt(self, plaintext):
        digraphs = self._prepare_text(plaintext)
        ciphertext = ""
        for pair in digraphs:
            a, b = pair[0], pair[1]
            ra, ca = self._pos(a)
            rb, cb = self._pos(b)

            if ra == rb:  # same row
                ciphertext += self.matrix[ra][(ca+1) % 5]
                ciphertext += self.matrix[rb][(cb+1) % 5]
            elif ca == cb:  # same column
                ciphertext += self.matrix[(ra+1) % 5][ca]
                ciphertext += self.matrix[(rb+1) % 5][cb]
            else:  # rectangle swap
                ciphertext += self.matrix[ra][cb]
                ciphertext += self.matrix[rb][ca]
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = ""
        i = 0
        while i < len(ciphertext):
            a, b = ciphertext[i], ciphertext[i+1]
            ra, ca = self._pos(a)
            rb, cb = self._pos(b)

            if ra == rb:  # same row
                plaintext += self.matrix[ra][(ca-1) % 5]
                plaintext += self.matrix[rb][(cb-1) % 5]
            elif ca == cb:  # same column
                plaintext += self.matrix[(ra-1) % 5][ca]
                plaintext += self.matrix[(rb-1) % 5][cb]
            else:  # rectangle swap
                plaintext += self.matrix[ra][cb]
                plaintext += self.matrix[rb][ca]
            i += 2
        return plaintext


if __name__ == "__main__":
    key = "GUIDANCE"
    msg = "The key is hidden under the door pad"

    pf = Playfair(key)
    enc = pf.encrypt(msg)
    dec = pf.decrypt(enc)

    print("Matrix:")
    for row in pf.matrix:
        print(row)

    print("\nPlaintext:", msg)
    print("Ciphertext:", enc)
    print("Decrypted:", dec)
