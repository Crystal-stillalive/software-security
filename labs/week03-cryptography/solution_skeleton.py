"""
Week 3 — FIX the misuse here. Fill in the TODOs.
pip install argon2-cffi pycryptodome
"""
import os, hashlib
from argon2 import PasswordHasher
from Crypto.Cipher import AES
 
ph = PasswordHasher()
 
def store_password(pw: str) -> str:
    # FIX: argon2id, salted automatically
    return ph.hash(pw)
 
def verify_password(hash_: str, pw: str) -> bool:
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False
 
def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    # FIX: authenticated encryption (AES-GCM), random nonce, key from env/KMS
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce, ct, tag
 
def decrypt_gcm(nonce: bytes, ct: bytes, tag: bytes, key: bytes) -> bytes:
    # Task 7: authenticated decryption — raises ValueError if ciphertext/tag were tampered with
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)
 
def reset_token() -> str:
    # FIX: CSPRNG
    import secrets
    return secrets.token_urlsafe(16)
 
# --- Task 6: rehash-on-login migration from legacy MD5 to argon2id ---
def is_legacy_md5(stored_value: str) -> bool:
    return len(stored_value) == 32 and all(c in "0123456789abcdef" for c in stored_value.lower())
 
def verify_and_maybe_upgrade(stored_value: str, pw: str, save_fn) -> bool:
    if is_legacy_md5(stored_value):
        if hashlib.md5(pw.encode()).hexdigest() == stored_value:
            save_fn(store_password(pw))
            return True
        return False
    return verify_password(stored_value, pw)
 
 
if __name__ == "__main__":
    key = bytes.fromhex(os.environ.get("ENC_KEY_HEX", os.urandom(32).hex()))
    h = store_password("password123")
    print("argon2 ok:", verify_password(h, "password123"))
    print("gcm:", encrypt_gcm(b"secret", key))
    print("token:", reset_token())
 
    # Task 6 demo: migrate a legacy MD5 record on login
    legacy = {"value": hashlib.md5(b"alicepw").hexdigest()}
 
    def save(new_hash):
        legacy["value"] = new_hash
        print("Upgraded to:", new_hash)
 
    print("Attempt 1 (legacy MD5):", verify_and_maybe_upgrade(legacy["value"], "alicepw", save))
    print("Stored value now:", legacy["value"])
    print("Attempt 2 (now argon2id):", verify_and_maybe_upgrade(legacy["value"], "alicepw", save))
 
    # Task 7: authenticated encryption round-trip + tamper-fails proof
    msg = b"secret message"
    nonce, ct, tag = encrypt_gcm(msg, key)
    print("Round-trip decrypt:", decrypt_gcm(nonce, ct, tag, key))
 
    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0xFF  # flip one byte
    try:
        decrypt_gcm(nonce, bytes(tampered_ct), tag, key)
        print("TAMPER NOT DETECTED — BUG")
    except ValueError as e:
        print("Tamper correctly detected:", e)
 
