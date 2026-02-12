#!/usr/bin/env python3

import os
import sys
import getpass
import hashlib
import hmac
import subprocess
import shutil
import tempfile
from datetime import datetime
from urllib.request import urlopen

VERSION = "1.0"

# Repo used for update checks
GITHUB_USER = "wiktorlaskowski"
GITHUB_REPO = "locker"
GITHUB_BRANCH = "initial"
REMOTE_VERSION_URL = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/{GITHUB_BRANCH}/VERSION"

HOME = os.path.expanduser("~")
USER = os.getenv("USER", "unknown")

CONFIG_DIR = os.path.join(HOME, ".config", "locker")
CONFIG_FILE = os.path.join(CONFIG_DIR, "locker.conf")

LOG_DIR = os.path.join(HOME, ".local", "share", "locker")
LOG_FILE = os.path.join(LOG_DIR, "locker.log")

BASE_DIR = os.getcwd()
LOCKER_DIR = os.path.join(BASE_DIR, "Locker")
LOCK_FILE = os.path.join(BASE_DIR, "locker.lck")

PBKDF2_ITERS = 200000
MAGIC = b"LOCKER5\n"


# ============================================================
# Logging
# ============================================================

def write_log(message):
    os.makedirs(LOG_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{message} [{timestamp}]\n")


def show_logs():
    if not os.path.exists(LOG_FILE):
        print("No logs found.")
        return
    with open(LOG_FILE, "r") as f:
        print(f.read())


# ============================================================
# Crypto helpers
# ============================================================

def pbkdf2_hash(text, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        text.encode("utf-8"),
        salt,
        PBKDF2_ITERS
    )


def openssl_encrypt_file(in_path, out_path, password):
    proc = subprocess.run(
        [
            "openssl", "enc",
            "-aes-256-cbc",
            "-salt",
            "-pbkdf2",
            "-iter", str(PBKDF2_ITERS),
            "-in", in_path,
            "-out", out_path,
            "-pass", "stdin"
        ],
        input=(password + "\n").encode("utf-8"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return proc.returncode == 0


def openssl_decrypt_file(in_path, out_path, password):
    proc = subprocess.run(
        [
            "openssl", "enc",
            "-d",
            "-aes-256-cbc",
            "-pbkdf2",
            "-iter", str(PBKDF2_ITERS),
            "-in", in_path,
            "-out", out_path,
            "-pass", "stdin"
        ],
        input=(password + "\n").encode("utf-8"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    return proc.returncode == 0


# ============================================================
# Config format (PIN + Recovery + Question)
# ============================================================
#
# locker.conf (binary):
#   salt_pin (16) + hash_pin (32)
#   salt_rec (16) + hash_rec (32)
#   qlen (2) + question bytes
#
# ============================================================

def write_config(pin, recovery_answer, question):
    os.makedirs(CONFIG_DIR, exist_ok=True)

    salt_pin = os.urandom(16)
    salt_rec = os.urandom(16)

    hash_pin = pbkdf2_hash(pin, salt_pin)
    hash_rec = pbkdf2_hash(recovery_answer, salt_rec)

    qbytes = question.encode("utf-8")
    qlen = len(qbytes).to_bytes(2, "big")

    blob = salt_pin + hash_pin + salt_rec + hash_rec + qlen + qbytes

    with open(CONFIG_FILE, "wb") as f:
        f.write(blob)

    os.chmod(CONFIG_FILE, 0o600)


def read_config():
    if not os.path.exists(CONFIG_FILE):
        return None

    with open(CONFIG_FILE, "rb") as f:
        data = f.read()

    if len(data) < 98:
        return None

    salt_pin = data[0:16]
    hash_pin = data[16:48]
    salt_rec = data[48:64]
    hash_rec = data[64:96]
    qlen = int.from_bytes(data[96:98], "big")
    qbytes = data[98:98 + qlen]

    try:
        question = qbytes.decode("utf-8")
    except Exception:
        return None

    return {
        "salt_pin": salt_pin,
        "hash_pin": hash_pin,
        "salt_rec": salt_rec,
        "hash_rec": hash_rec,
        "question": question
    }


def delete_config():
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)


# ============================================================
# locker.lck format
# ============================================================
#
# MAGIC "LOCKER5\n"
# 4 bytes  len(enc_master_pin)
# 4 bytes  len(enc_master_rec)
# 8 bytes  len(enc_data)
# 32 bytes HMAC-SHA256(master_key, enc_master_pin||enc_master_rec||enc_data)
# bytes    enc_master_pin
# bytes    enc_master_rec
# bytes    enc_data
#
# HMAC key = raw master key (32 bytes)
#
# ============================================================

def write_locker_file(enc_master_pin, enc_master_rec, enc_data, master_key):
    h = hmac.new(master_key, enc_master_pin + enc_master_rec + enc_data, hashlib.sha256).digest()

    with open(LOCK_FILE, "wb") as f:
        f.write(MAGIC)
        f.write(len(enc_master_pin).to_bytes(4, "big"))
        f.write(len(enc_master_rec).to_bytes(4, "big"))
        f.write(len(enc_data).to_bytes(8, "big"))
        f.write(h)
        f.write(enc_master_pin)
        f.write(enc_master_rec)
        f.write(enc_data)


def read_locker_file():
    if not os.path.exists(LOCK_FILE):
        return None

    with open(LOCK_FILE, "rb") as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            return None

        l1 = int.from_bytes(f.read(4), "big")
        l2 = int.from_bytes(f.read(4), "big")
        l3 = int.from_bytes(f.read(8), "big")

        stored_hmac = f.read(32)

        enc_master_pin = f.read(l1)
        enc_master_rec = f.read(l2)
        enc_data = f.read(l3)

    if len(enc_master_pin) != l1 or len(enc_master_rec) != l2 or len(enc_data) != l3:
        return None

    return {
        "stored_hmac": stored_hmac,
        "enc_master_pin": enc_master_pin,
        "enc_master_rec": enc_master_rec,
        "enc_data": enc_data
    }


# ============================================================
# Helper
# ============================================================

def safe_delete(path):
    if os.path.isdir(path):
        shutil.rmtree(path)
    elif os.path.exists(path):
        os.remove(path)


def prompt_pin():
    while True:
        p1 = getpass.getpass("Set new PIN: ")
        p2 = getpass.getpass("Confirm PIN: ")
        if p1 == p2 and p1.strip():
            return p1
        print("PIN mismatch or empty.")


def prompt_recovery():
    while True:
        q = input("Recovery question: ").strip()
        if q:
            break
        print("Recovery question cannot be empty.")

    while True:
        a1 = getpass.getpass("Recovery answer: ")
        a2 = getpass.getpass("Confirm recovery answer: ")
        if a1 == a2 and a1.strip():
            return q, a1
        print("Recovery answer mismatch or empty.")


def verify_pin(config):
    pin = getpass.getpass("Enter PIN: ")
    test = pbkdf2_hash(pin, config["salt_pin"])
    if test == config["hash_pin"]:
        return pin
    print("Incorrect PIN.")
    sys.exit(1)


def verify_recovery_answer(config):
    print(f"Recovery question: {config['question']}")
    ans = getpass.getpass("Enter recovery answer: ")
    test = pbkdf2_hash(ans, config["salt_rec"])
    if test == config["hash_rec"]:
        return ans
    print("Incorrect recovery answer.")
    sys.exit(1)


# ============================================================
# Lock / Unlock
# ============================================================

def lock():
    if not os.path.exists(LOCKER_DIR):
        print("Locker directory not found.")
        sys.exit(1)

    if os.path.exists(LOCK_FILE):
        print("locker.lck already exists. Unlock first.")
        sys.exit(1)

    delete_config()

    pin = prompt_pin()
    question, recovery_answer = prompt_recovery()

    write_config(pin, recovery_answer, question)

    with tempfile.TemporaryDirectory() as td:
        tar_path = os.path.join(td, "locker.tar")
        subprocess.run(["tar", "-cf", tar_path, "Locker"], check=True)

        # Random master key
        master_key = os.urandom(32)
        mk_path = os.path.join(td, "master.bin")
        with open(mk_path, "wb") as f:
            f.write(master_key)

        # Encrypt master key with PIN and recovery
        enc_master_pin_path = os.path.join(td, "mk_pin.bin")
        enc_master_rec_path = os.path.join(td, "mk_rec.bin")

        if not openssl_encrypt_file(mk_path, enc_master_pin_path, pin):
            print("Encryption failed (PIN key stage).")
            sys.exit(1)

        if not openssl_encrypt_file(mk_path, enc_master_rec_path, recovery_answer):
            print("Encryption failed (recovery key stage).")
            sys.exit(1)

        # Encrypt tar using master key as hex password
        master_pass = master_key.hex()
        enc_data_path = os.path.join(td, "data.bin")

        if not openssl_encrypt_file(tar_path, enc_data_path, master_pass):
            print("Encryption failed (data stage).")
            sys.exit(1)

        with open(enc_master_pin_path, "rb") as f:
            enc_master_pin = f.read()
        with open(enc_master_rec_path, "rb") as f:
            enc_master_rec = f.read()
        with open(enc_data_path, "rb") as f:
            enc_data = f.read()

        write_locker_file(enc_master_pin, enc_master_rec, enc_data, master_key)

    safe_delete(LOCKER_DIR)
    print("Locker locked.")


def unlock(use_recovery=False, silent=False):
    if not os.path.exists(LOCK_FILE):
        if not silent:
            print("No locker.lck found.")
        return False

    config = read_config()
    if not config:
        print("No valid config found. Cannot unlock.")
        return False

    blob = read_locker_file()
    if not blob:
        write_log(f"ALERT: User {USER} unexpectedly tampered with the encrypted file. The file will not unlock.")
        print("Tamper detected: invalid locker file header.")
        return False

    # Step 1: decrypt master key
    with tempfile.TemporaryDirectory() as td:
        mk_enc_path = os.path.join(td, "mk_enc.bin")
        mk_out_path = os.path.join(td, "master.bin")

        if use_recovery:
            recovery_answer = verify_recovery_answer(config)
            with open(mk_enc_path, "wb") as f:
                f.write(blob["enc_master_rec"])
            if not openssl_decrypt_file(mk_enc_path, mk_out_path, recovery_answer):
                print("Recovery unlock failed.")
                return False
        else:
            pin = verify_pin(config)
            with open(mk_enc_path, "wb") as f:
                f.write(blob["enc_master_pin"])
            if not openssl_decrypt_file(mk_enc_path, mk_out_path, pin):
                print("PIN unlock failed.")
                return False

        with open(mk_out_path, "rb") as f:
            master_key = f.read()

        if len(master_key) != 32:
            write_log(f"ALERT: User {USER} unexpectedly tampered with the encrypted file. The file will not unlock.")
            print("Tamper detected: master key corrupted.")
            return False

        # Step 2: verify HMAC using master key
        calc = hmac.new(master_key, blob["enc_master_pin"] + blob["enc_master_rec"] + blob["enc_data"], hashlib.sha256).digest()

        if not hmac.compare_digest(blob["stored_hmac"], calc):
            write_log(f"ALERT: User {USER} unexpectedly tampered with the encrypted file. The file will not unlock.")
            print("Tamper detected: authentication failed.")
            return False

        # Step 3: decrypt data tar using master key
        master_pass = master_key.hex()
        enc_data_path = os.path.join(td, "data.bin")
        tar_out_path = os.path.join(td, "locker.tar")

        with open(enc_data_path, "wb") as f:
            f.write(blob["enc_data"])

        if not openssl_decrypt_file(enc_data_path, tar_out_path, master_pass):
            write_log(f"ALERT: User {USER} unexpectedly tampered with the encrypted file. The file will not unlock.")
            print("Decryption failed (corrupted data).")
            return False

        subprocess.run(["tar", "-xf", tar_out_path], check=True)

    # Success:
    safe_delete(LOCK_FILE)
    delete_config()

    if use_recovery:
        write_log(
            f"Warning: User {USER} unlocked the vault using your recovery question. "
            f"If this was not you or you were away from your computer, secure your locker now by using a different password on the next lock."
        )

    if not silent:
        print("Locker unlocked. PIN discarded.")

    return True


# ============================================================
# Git update system
# ============================================================

def parse_version(v):
    # "1.0" -> (1,0)
    parts = v.strip().split(".")
    out = []
    for p in parts:
        try:
            out.append(int(p))
        except ValueError:
            out.append(0)
    return tuple(out)


def get_remote_version():
    try:
        with urlopen(REMOTE_VERSION_URL, timeout=5) as r:
            data = r.read().decode("utf-8", errors="ignore").strip()
        return data
    except Exception:
        return None


def check_update():
    remote = get_remote_version()
    if not remote:
        print("Could not check updates (network or GitHub unreachable).")
        return

    if parse_version(remote) > parse_version(VERSION):
        print(f"Update available: {VERSION} -> {remote}")
        print("Run: ./locker.py --update")
    else:
        print(f"No update available. Current version: {VERSION}")


def do_update():
    # If locked, require unlock first (important for future migrations)
    if os.path.exists(LOCK_FILE) and not os.path.exists(LOCKER_DIR):
        print("Locker is currently locked.")
        print("For safety, you must unlock before updating.")
        print("Enter PIN to unlock, or use --RECOVERY if needed.")
        print("")

        ok = unlock(use_recovery=False, silent=True)
        if not ok:
            print("Update aborted.")
            sys.exit(1)

        print("Locker successfully unlocked for update safety.")

    # Ensure this is a git repo
    if not os.path.exists(os.path.join(BASE_DIR, ".git")):
        print("This folder is not a Git repository.")
        print("Clone your repo here first, then run --update.")
        sys.exit(1)

    # Pull updates
    proc = subprocess.run(["git", "pull"], check=False)
    if proc.returncode != 0:
        print("Git update failed.")
        sys.exit(1)

    print("Update complete.")
    print("Run the script again.")


# ============================================================
# Main
# ============================================================

def main():
    args = sys.argv[1:]

    if "--version" in args:
        print(VERSION)
        return

    if "--logs" in args:
        show_logs()
        return

    if "--check-update" in args:
        check_update()
        return

    if "--update" in args:
        do_update()
        return

    use_recovery = "--RECOVERY" in args

    locked = os.path.exists(LOCK_FILE)
    unlocked = os.path.exists(LOCKER_DIR)

    # LOCKED
    if locked and not unlocked:
        unlock(use_recovery=use_recovery)
        return

    # UNLOCKED
    if unlocked and not locked:
        if use_recovery:
            print("--RECOVERY is only valid when locked.")
            sys.exit(1)
        lock()
        return

    # FIRST RUN
    if not locked and not unlocked:
        print("No Locker found. Creating Locker directory.")
        os.makedirs(LOCKER_DIR)
        print("Place files inside Locker/ and run again.")
        return

    # INCONSISTENT
    print("Inconsistent state detected.")
    print("You likely have BOTH Locker/ and locker.lck.")
    sys.exit(1)


if __name__ == "__main__":
    main()
