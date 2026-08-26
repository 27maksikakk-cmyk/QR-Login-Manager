
---

# Код на 8 языках программирования

## 1. Python (`qr_login_manager.py`)

```python
# qr_login_manager.py
import argparse
import json
import os
import sys
import secrets
import string
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import qrcode
from PIL import Image
from colorama import init, Fore, Style

init(autoreset=True)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext

def decrypt_data(encrypted: bytes, password: str) -> bytes:
    salt = encrypted[:16]
    nonce = encrypted[16:28]
    ciphertext = encrypted[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def generate_codes(count: int, length: int = 8) -> list:
    alphabet = string.ascii_uppercase + string.digits
    return [''.join(secrets.choice(alphabet) for _ in range(length)) for _ in range(count)]

def save_to_file(data: dict, password: str, filename: str):
    json_data = json.dumps(data).encode()
    encrypted = encrypt_data(json_data, password)
    with open(filename, 'wb') as f:
        f.write(encrypted)
    print(Fore.GREEN + f"Saved encrypted backup to {filename}")

def load_from_file(filename: str, password: str) -> dict:
    with open(filename, 'rb') as f:
        encrypted = f.read()
    decrypted = decrypt_data(encrypted, password)
    return json.loads(decrypted.decode())

def list_codes(filename: str, password: str):
    data = load_from_file(filename, password)
    print(Fore.CYAN + f"Backup: {filename}")
    print(Fore.YELLOW + f"Created: {data['created']}")
    print(Fore.GREEN + "Codes:")
    for code in data['codes']:
        print(f"  {code}")

def generate_qr(filename: str, password: str, output: str):
    data = load_from_file(filename, password)
    # Создаём строку с кодами для QR
    codes_str = '\n'.join(data['codes'])
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(codes_str)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output)
    print(Fore.GREEN + f"QR code saved to {output}")

def check_code(filename: str, password: str, code: str):
    data = load_from_file(filename, password)
    if code in data['codes']:
        print(Fore.GREEN + f"Code '{code}' is valid (found in backup).")
    else:
        print(Fore.RED + f"Code '{code}' is NOT in backup.")

def main():
    parser = argparse.ArgumentParser(description="QR Login Manager - backup codes")
    parser.add_argument("--generate", type=int, help="Generate N backup codes")
    parser.add_argument("--output", help="Output file for encrypted backup")
    parser.add_argument("--password", help="Password for encryption/decryption")
    parser.add_argument("--list", metavar="FILE", help="List codes from encrypted file")
    parser.add_argument("--qr", metavar="FILE", help="Generate QR code from backup file")
    parser.add_argument("--check", metavar="CODE", help="Check if code exists in backup")
    parser.add_argument("--export-json", help="Export decrypted data to JSON")
    parser.add_argument("--import-json", help="Import from JSON and encrypt with password")
    args = parser.parse_args()

    if args.generate:
        if not args.output or not args.password:
            print(Fore.RED + "Error: --output and --password required for generation")
            sys.exit(1)
        codes = generate_codes(args.generate)
        data = {"created": str(__import__('datetime').datetime.utcnow()), "codes": codes}
        save_to_file(data, args.password, args.output)

    elif args.list:
        if not args.password:
            print(Fore.RED + "Error: --password required")
            sys.exit(1)
        list_codes(args.list, args.password)

    elif args.qr:
        if not args.password:
            print(Fore.RED + "Error: --password required")
            sys.exit(1)
        qr_output = args.output or "qrcodes.png"
        generate_qr(args.qr, args.password, qr_output)

    elif args.check:
        if not args.password:
            print(Fore.RED + "Error: --password required")
            sys.exit(1)
        check_code(args.list, args.password, args.check)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
