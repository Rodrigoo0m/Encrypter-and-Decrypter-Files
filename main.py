from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = P8KDF2HMAC (
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str) -> None:
    with open(file_path, "rb") as file:
        data = file.read()

    salt = os.urandom(16)
    key = generate_key(password, salt)

    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path, "wb") as file:
        file.write(encrypted_data)

def decrypt_file(file_path: str, password: str) -> None:
    with open(file_path, "rb") as file:
        file_data = file.read()

        salt = file_data[:16]
        iv = file_data[16:32]
        encrypt_data = file_data[32:]

        key = generate_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        with open(file_path, "wb") as file:
            file.write(data)

def main():
    file_path = input("Enter file path: ")
    password = input("Enter password: ")

    action = input("Enter 'E' to encrypt or 'D' to decrypt: ").upper()

    if action == 'E':
        encrypt_file(file_path, password)
        print("File encrypted successfully.")
    elif action == 'D':
        decrypt_file(file_path, password)
        print("File decrypted successfully.")
    else:
        print("Invalid action. Please enter 'E' to encrypt or 'D' to decrypt.")

if __name__ == "__main__":
    main()
