# Locker

Locker is a simple, Linux Mint-friendly command-line tool that encrypts and decrypts a `Locker/` folder in the current directory.

It is designed for daily use and works like a hotel safe:

* Every time you lock the folder, you set a new PIN
* Unlocking requires the same PIN
* After unlocking, the PIN is discarded

Locker also supports recovery unlocking using a personal recovery question.

---

## Features

* Encrypts and decrypts a `Locker/` folder in the current directory
* One-time PIN per lock cycle (hotel safe style)
* Recovery question + answer support (`--RECOVERY`)
* Tamper detection (HMAC authentication)
* Security warning logs (`--logs`)
* No Python packages required (no pip)
* Uses system tools available on Linux Mint (OpenSSL + tar)

---

## Requirements

* Linux Mint (or similar Debian-based distro)
* Python 3 (system Python)
* OpenSSL
* tar
* git (recommended for install + updates)

---

## Installation (Recommended: Git)

Clone the repository:

```bash
git clone https://github.com/wiktorlaskowski/locker.git
cd locker
```

Make the script executable:

```bash
chmod +x locker.py
```

---

## Usage

### First Run

Run the script inside the directory where you want your vault:

```bash
./locker.py
```

If no `Locker/` folder exists, it will create one.

Put files inside `Locker/`, then run again to lock it.

---

## Locking (Encrypting)

If `Locker/` exists and `locker.lck` does not, running the script will lock the folder:

```bash
./locker.py
```

You will be asked to:

* Set a new PIN
* Set a recovery question
* Set a recovery answer

After locking:

* `Locker/` is deleted
* `locker.lck` is created

---

## Unlocking (Decrypting)

If `locker.lck` exists and `Locker/` does not, running the script will unlock the vault:

```bash
./locker.py
```

If the PIN is correct:

* `Locker/` is restored
* `locker.lck` is deleted
* The PIN is discarded

---

## Recovery Unlock

If you forgot your PIN, you can unlock using your recovery question:

```bash
./locker.py --RECOVERY
```

If the recovery answer is correct:

* The vault unlocks successfully
* A warning is written to the logs

---

## Logs

Locker writes warnings and alerts to:

* `~/.local/share/locker/locker.log`

To view logs:

```bash
./locker.py --logs
```

Example log events include:

* Tamper detection alerts
* Recovery unlock warnings

---

## Update

Locker supports updating through GitHub.

### Check for updates

```bash
./locker.py --check-update
```

### Update

```bash
./locker.py --update
```

Important:

* If the locker is locked, Locker will require unlocking before updating (for safety and future encryption migrations).

---

## File Layout

Unlocked state:

* `Locker/`
* `locker.py`

Locked state:

* `locker.lck`
* `locker.py`

Config and logs:

* `~/.config/locker/locker.conf`
* `~/.local/share/locker/locker.log`

---

## Security Notes

* Your PIN and recovery answer are never stored in plaintext
* Both are stored as salted PBKDF2 hashes
* The encrypted vault file includes tamper protection (authentication)
* If tampering is detected, Locker will refuse to unlock and will log an alert

---

## Warning

If you lose both:

* the PIN
* and the recovery answer

Your data cannot be recovered.

This is real encryption by design.

---

## License

MIT License
