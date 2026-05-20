# Task 2 - Secure File Transfer Application
# Rhombix Technologies Cybersecurity Internship
# Features: AES-256 Encryption, HMAC Integrity, Access Control, Audit Logs

import os, json, hashlib, hmac, base64, datetime, getpass
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# app folders and files
VAULT_DIR    = "transfer_vault"       # encrypted files stored here
OUTPUT_DIR   = "received_files"       # decrypted files saved here
USER_DB      = "users.json"           # hashed user credentials
LOG_FILE     = "audit_log.txt"        # timestamped activity log

os.makedirs(VAULT_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

#derive strong AES-256 key from password using PBKDF2
def build_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000, backend=default_backend())
    return kdf.derive(password.encode())

# encrypt file with AES-256-CBC + HMAC integrity tag
def encrypt_file(filepath, passwd):
    with open(filepath, "rb") as f:
        raw = f.read()
    salt, iv = os.urandom(16), os.urandom(16)
    key = build_key(passwd, salt)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(raw) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()
    cipher_data = enc.update(padded) + enc.finalize()
    tag = hmac.new(key, cipher_data, hashlib.sha256).digest()  # integrity tag
    bundle = base64.b64encode(salt + iv + tag + cipher_data)
    vault_path = os.path.join(VAULT_DIR, Path(filepath).name + ".vault")
    with open(vault_path, "wb") as f:
        f.write(bundle)
    checksum = hashlib.sha256(raw).hexdigest()
    write_log("FILE_ENCRYPTED", filepath, f"vault={vault_path}")
    print(f"\n[OK] Encrypted → {vault_path}\n[#]  Checksum : {checksum}")
    return checksum

# ---- decrypt vault file, verify HMAC, save output ----
def decrypt_file(vault_path, passwd, expected_checksum=None):
    with open(vault_path, "rb") as f:
        data = base64.b64decode(f.read())
    salt, iv, stored_tag, cipher_data = data[:16], data[16:32], data[32:64], data[64:]
    key = build_key(passwd, salt)
    computed_tag = hmac.new(key, cipher_data, hashlib.sha256).digest()
    if not hmac.compare_digest(stored_tag, computed_tag):  # tamper check
        write_log("INTEGRITY_FAIL", vault_path, "HMAC mismatch")
        print("\n[ALERT] Integrity check FAILED — file may be tampered!"); return
    dec = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded_plain = dec.update(cipher_data) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded_plain) + unpadder.finalize()
    if expected_checksum:
        match = hashlib.sha256(plain).hexdigest() == expected_checksum
        print(f"\n[{'OK' if match else 'WARN'}] Checksum {'verified' if match else 'mismatch'}!")
    out_path = os.path.join(OUTPUT_DIR, Path(vault_path).stem)
    with open(out_path, "wb") as f:
        f.write(plain)
    write_log("FILE_DECRYPTED", vault_path, "success")
    print(f"[OK] Decrypted → {out_path}")

# ---- append timestamped entry to audit log ----
def write_log(action, target, note=""):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {action:<20} | {target:<35} | {note}\n")

def show_log():
    print("\n===== AUDIT LOG =====")
    if not os.path.exists(LOG_FILE): print("Empty."); return
    lines = open(LOG_FILE).readlines()
    [print(l.strip()) for l in lines[-15:]]
    print("=====================")

# user registry: SHA-256 hashed passwords in JSON
def load_users():
    return json.load(open(USER_DB)) if os.path.exists(USER_DB) else {}

def save_users(db):
    json.dump(db, open(USER_DB, "w"), indent=2)

def hash_pw(pw):
    return hashlib.sha256(("sec_" + pw).encode()).hexdigest()

def register():
    uname = input("New username: ").strip()
    db = load_users()
    if uname in db: print("[!] Username taken."); return
    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Confirm: "): print("[!] Mismatch."); return
    db[uname] = hash_pw(pw); save_users(db)
    write_log("REGISTERED", uname)
    print(f"[+] User '{uname}' created!")

def login():
    uname = input("Username: ").strip()
    pw = getpass.getpass("Password: ")
    db = load_users()
    if db.get(uname) != hash_pw(pw):
        write_log("LOGIN_FAIL", uname); print("[!] Invalid credentials."); return None
    write_log("LOGIN_OK", uname); print(f"[+] Welcome, {uname}!"); return uname

# menus
def main_menu():
    print("\n" + "="*40 + "\n  Secure File Transfer | Rhombix Tech\n" + "="*40)
    print("  [1] Register  [2] Login  [3] Exit")

def user_menu(u):
    print(f"\n[{u}] >> [1] Encrypt  [2] Decrypt  [3] Audit Log  [4] Logout")

# main app loop
def run():
    user = None
    while True:
        if not user:
            main_menu()
            c = input("Choice: ").strip()
            if c == "1": register()
            elif c == "2": user = login()
            elif c == "3": print("Stay Secure!"); break
        else:
            user_menu(user)
            c = input("Choice: ").strip()
            if c == "1":
                fp = input("File path to encrypt: ").strip()
                if os.path.isfile(fp): encrypt_file(fp, getpass.getpass("Transfer password: "))
                else: print("[!] File not found.")
            elif c == "2":
                files = [f for f in os.listdir(VAULT_DIR) if f.endswith(".vault")]
                if not files: print("[!] No vault files found."); continue
                [print(f"  [{i+1}] {f}") for i, f in enumerate(files)]
                pick = input("Pick number: ").strip()
                if pick.isdigit() and 1 <= int(pick) <= len(files):
                    vp = os.path.join(VAULT_DIR, files[int(pick)-1])
                    pw = getpass.getpass("Transfer password: ")
                    chk = input("Expected checksum (Enter to skip): ").strip()
                    decrypt_file(vp, pw, chk or None)
            elif c == "3": show_log()
            elif c == "4": write_log("LOGOUT", user); user = None
            else: print("[!] Invalid.")

if __name__ == "__main__":
    run()
