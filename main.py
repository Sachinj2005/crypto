
import os
import sys
import secrets
import string
import hashlib

from pathlib import Path
from getpass import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag


# =========================================
# SECUREVAULT PRO - CRYPTOGRAPHY CONFIGURATION
# =========================================

MAGIC = b"ACV1"
SALT_SIZE = 16
NONCE_SIZE = 12
HEADER_SIZE = 32

CHUNK_SIZE = 1024 * 1024


# =========================================
# 1. PASSWORD-BASED KEY DERIVATION
# =========================================

def generate_key(password, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )

    return kdf.derive(password.encode("utf-8"))


# =========================================
# 2. AES-256-GCM FILE ENCRYPTION
# =========================================

def encrypt_file(filename):

    source = Path(filename)

    if not source.is_file():
        print("File not found!")
        return

    print("\n===== FILE ENCRYPTION =====")

    password = getpass("Create password: ")
    confirm = getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match!")
        return

    if len(password) < 12:
        print("Password must contain at least 12 characters.")
        return

    data = source.read_bytes()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = generate_key(password, salt)
    aes = AESGCM(key)

    header = MAGIC + salt + nonce

    encrypted = aes.encrypt(
        nonce,
        data,
        header
    )

    output = Path(str(source) + ".enc")

    with output.open("xb") as file:
        file.write(header + encrypted)

    print("\nEncryption successful!")
    print("Algorithm: AES-256-GCM")
    print("Encrypted file:", output)


# =========================================
# 3. AUTHENTICATED FILE DECRYPTION
# =========================================

def authenticated_decrypt(filename, password):

    source = Path(filename)

    if not source.name.endswith(".enc"):
        raise ValueError("Expected a .enc file.")

    data = source.read_bytes()

    if len(data) < HEADER_SIZE + 16:
        raise ValueError("Invalid encrypted file.")

    if data[:4] != MAGIC:
        raise ValueError("Unsupported encrypted file format.")

    salt = data[4:20]
    nonce = data[20:32]
    ciphertext = data[32:]

    key = generate_key(password, salt)
    aes = AESGCM(key)

    try:
        return aes.decrypt(
            nonce,
            ciphertext,
            data[:HEADER_SIZE]
        )

    except InvalidTag:
        raise ValueError(
            "Wrong password or file tampering detected!"
        )


def decrypt_file(filename):

    print("\n===== FILE DECRYPTION =====")

    password = getpass("Enter password: ")

    decrypted = authenticated_decrypt(
        filename,
        password
    )

    source = Path(filename)
    original = Path(source.name[:-4])

    output = source.with_name(
        original.stem + "_decrypted" + original.suffix
    )

    with output.open("xb") as file:
        file.write(decrypted)

    print("\nDecryption successful!")
    print("Recovered file:", output)


# =========================================
# 4. ENCRYPTED FILE AUTHENTICITY VERIFICATION
# =========================================

def verify_file(filename):

    print("\n===== FILE AUTHENTICITY CHECK =====")

    password = getpass("Enter password: ")

    # Decrypt and authenticate in memory.
    # No recovered file is written to disk.
    authenticated_decrypt(filename, password)

    print("\nAuthentication: PASSED")
    print("Correct key and valid AES-GCM authentication tag.")
    print("No decrypted output file was created.")


# =========================================
# 5. SHA-256 FILE HASHING
# =========================================

def calculate_hash(filename):

    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


def show_hash(filename):

    print("\n===== SHA-256 FILE HASH =====")

    result = calculate_hash(filename)

    print("File:", filename)
    print("SHA-256:", result)


# =========================================
# 6. FILE INTEGRITY COMPARISON
# =========================================

def compare_files(file1, file2):

    print("\n===== FILE INTEGRITY CHECK =====")

    hash1 = calculate_hash(file1)
    hash2 = calculate_hash(file2)

    print("File 1:", file1)
    print("SHA-256:", hash1)

    print("\nFile 2:", file2)
    print("SHA-256:", hash2)

    if hash1 == hash2:
        print("\nRESULT: Files match.")
        print("Both files have identical SHA-256 hashes.")
    else:
        print("\nRESULT: Files differ.")
        print("The SHA-256 hashes do not match.")


# =========================================
# 7. CRYPTOGRAPHIC PASSWORD GENERATOR
# =========================================

def generate_password(length=16):

    if length < 12:
        raise ValueError(
            "Password length must be at least 12."
        )

    groups = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        "!@#$%^&*()-_=+?"
    ]

    alphabet = "".join(groups)

    # Include at least one character per group
    password = [
        secrets.choice(group)
        for group in groups
    ]

    for _ in range(length - len(password)):
        password.append(secrets.choice(alphabet))

    secrets.SystemRandom().shuffle(password)

    print("\n===== SECURE PASSWORD GENERATOR =====")
    print("Generated password:", "".join(password))
    print("Length:", length)


# =========================================
# 8. ENCRYPTED FILE INSPECTOR
# =========================================

def inspect_file(filename):

    print("\n===== ENCRYPTED FILE INSPECTOR =====")

    source = Path(filename)
    data = source.read_bytes()

    if len(data) < HEADER_SIZE + 16:
        raise ValueError("Invalid encrypted file.")

    if data[:4] != MAGIC:
        raise ValueError("Unsupported file format.")

    salt = data[4:20]
    nonce = data[20:32]

    encrypted_size = len(data) - HEADER_SIZE

    print("File:", source.name)
    print("Format:", MAGIC.decode())
    print("Algorithm: AES-256-GCM")
    print("Key derivation: Scrypt")
    print("Salt:", salt.hex())
    print("Nonce:", nonce.hex())
    print("Encrypted payload bytes:", encrypted_size)
    print("Total file bytes:", len(data))
    print("\nNote: Inspection does not authenticate the file.")


# =========================================
# 9. COMMAND LINE INTERFACE
# =========================================

def show_menu():

    print("\n========================================")
    print("       SECUREVAULT PRO")
    print("   Applied Cryptography Coding Challenge")
    print("========================================")

    print("\nAvailable commands:")
    print(" encrypt <file>")
    print(" decrypt <file.enc>")
    print(" verify <file.enc>")
    print(" hash <file>")
    print(" compare <file1> <file2>")
    print(" password [length]")
    print(" inspect <file.enc>")

    print("\nExample:")
    print("python main.py encrypt sample.txt")


def main():

    if len(sys.argv) < 2:
        show_menu()
        return

    command = sys.argv[1].lower()

    try:

        if command == "encrypt" and len(sys.argv) == 3:
            encrypt_file(sys.argv[2])

        elif command == "decrypt" and len(sys.argv) == 3:
            decrypt_file(sys.argv[2])

        elif command == "verify" and len(sys.argv) == 3:
            verify_file(sys.argv[2])

        elif command == "hash" and len(sys.argv) == 3:
            show_hash(sys.argv[2])

        elif command == "compare" and len(sys.argv) == 4:
            compare_files(sys.argv[2], sys.argv[3])

        elif command == "password" and len(sys.argv) in (2, 3):
            length = int(sys.argv[2]) if len(sys.argv) == 3 else 16
            generate_password(length)

        elif command == "inspect" and len(sys.argv) == 3:
            inspect_file(sys.argv[2])

        else:
            show_menu()

    except (OSError, ValueError) as error:
        print("\nError:", error)


if __name__ == "__main__":
    main()
