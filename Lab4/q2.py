# q2.py — tiny Rabin KMS (demo). Requires pycryptodome: pip install pycryptodome
from Crypto.Util import number
from datetime import datetime, timedelta, timezone

# tiny in-memory store
KS = {}

def now_utc():
    return datetime.now(timezone.utc)

def gen_rabin(bits=512):
    while True:
        p = number.getPrime(bits//2)
        if p % 4 == 3: break
    while True:
        q = number.getPrime(bits//2)
        if q % 4 == 3 and q != p: break
    return {"n": p*q, "p": p, "q": q,
            "created": now_utc(), "expires": now_utc()+timedelta(days=365), "revoked": False}

def create(id_, bits=512):
    KS[id_] = gen_rabin(bits); print(f"[LOG] Created keys for {id_}")

def public(id_):
    r = KS.get(id_)
    return None if not r or r["revoked"] else {"n": r["n"], "expires": r["expires"].isoformat()}

def private(id_):
    r = KS.get(id_)
    return None if not r or r["revoked"] else {"p": r["p"], "q": r["q"]}

def revoke(id_):
    if id_ in KS:
        KS[id_]["revoked"] = True; print(f"[LOG] Revoked {id_}")

def renew(id_, bits=512):
    if id_ in KS:
        KS[id_] = gen_rabin(bits); print(f"[LOG] Renewed keys for {id_}")

if __name__ == "__main__":
    create("HospitalA")
    print("Public:", public("HospitalA"))
    print("Private:", private("HospitalA"))
    revoke("HospitalA")
    print("After revocation -> Public:", public("HospitalA"))
    renew("HospitalA")
    print("After renewal -> Public:", public("HospitalA"))
