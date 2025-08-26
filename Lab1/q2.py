import string

charset = string.ascii_uppercase

class Vigenere:
    def __init__(self, msg, key):
        self.pt = msg.replace(" ", "").upper()
        self.key = key.upper()
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        key_stream = (self.key * ((len(self.pt)//len(self.key))+1))[:len(self.pt)]
        for p, k in zip(self.pt, key_stream):
            c = charset[(charset.index(p) + charset.index(k)) % 26]
            self.ct += c
        return self.ct

    def decrypt(self):
        pt = ""
        key_stream = (self.key * ((len(self.ct)//len(self.key))+1))[:len(self.ct)]
        for c, k in zip(self.ct, key_stream):
            p = charset[(charset.index(c) - charset.index(k)) % 26]
            pt += p
        return pt


class Autokey:
    def __init__(self, msg, key):
        self.pt = msg.replace(" ", "").upper()
        self.key = key 
        self.ct = ""

    def encrypt(self):
        self.ct = ""
        key_stream = [self.key] + [charset.index(ch) for ch in self.pt[:-1]]
        for p, k in zip(self.pt, key_stream):
            c = charset[(charset.index(p) + k) % 26]
            self.ct += c
        return self.ct

    def decrypt(self):
        pt = ""
        key_stream = [self.key]
        for c in self.ct:
            k = key_stream[-1] if isinstance(key_stream[-1], int) else charset.index(key_stream[-1])
            p = charset[(charset.index(c) - k) % 26]
            pt += p
            key_stream.append(charset.index(p))
        return pt


if __name__ == "__main__":
    msg = "the house is being sold tonight"

    v = Vigenere(msg, "dollars")
    enc_v = v.encrypt()
    dec_v = v.decrypt()
    print("Vigenere Encrypt:", enc_v)
    print("Vigenere Decrypt:", dec_v)

    a = Autokey(msg, 7)
    enc_a = a.encrypt()
    dec_a = a.decrypt()
    print("Autokey Encrypt:", enc_a)
    print("Autokey Decrypt:", dec_a)
