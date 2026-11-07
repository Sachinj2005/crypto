# SecureVault Pro

A small Python cryptography project for learning authenticated file encryption and integrity verification.

## Features

- AES-256-GCM authenticated file encryption.
- Scrypt password-based key derivation with a random salt.
- Random nonce and authenticated header for every encrypted file.
- Safe decryption that rejects a wrong password or tampered ciphertext.
- SHA-256 hashing and file comparison.
- Cryptographically secure password generation.
- Encrypted-file metadata inspection.
- Optional Tkinter desktop dashboard in `gui.py`.

## Project files

- `main.py` — command-line application.
- `gui.py` — optional desktop interface.
- `tamper_test.py` — creates a modified ciphertext for authentication testing.
- `sample.txt` — synthetic plaintext fixture.
- `sample.enc`, `sample.txt.enc`, and `sample_tampered.txt.enc` — sample encryption fixtures.
- `sample_decrypted.txt` and `recovered.txt` — expected plaintext examples.

The sample files contain demonstration text only. Do not add real confidential files, passwords, private keys, API keys, or credentials to this repository.

## Setup

Python 3.10 or newer is recommended.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

The optional GUI requires Tkinter, which is included with most standard Windows Python installations.

## Command-line usage

```powershell
python main.py encrypt sample.txt
python main.py decrypt sample.txt.enc
python main.py verify sample.txt.enc
python main.py hash sample.txt
python main.py compare sample.txt recovered.txt
python main.py password 20
python main.py inspect sample.txt.enc
```

Encryption and decryption request passwords interactively and enforce a minimum length of 12 characters. Never place a real password in a command, source file, README, or Git history.

## Tamper detection

To test authenticated encryption locally, make a copy of an encrypted fixture, modify the copy with `tamper_test.py`, and run:

```powershell
python main.py verify sample_tampered.txt.enc
```

Verification should reject the altered authentication tag. The original encrypted fixture should remain unchanged.

## GUI

Run the optional desktop dashboard with:

```powershell
python gui.py
```

Use the GUI only with test files until you have reviewed the code and chosen an appropriate key-management process. This project is an educational example, not a replacement for a managed secrets or enterprise key-management system.
