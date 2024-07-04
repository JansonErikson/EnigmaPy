import os
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import time

def generate_key(password, salt):
    """
    Derive a secure encryption key from a password and salt.
    
    This function uses PBKDF2 to protect against brute-force and rainbow table attacks.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    """
    Encrypt a file using AES-GCM for confidentiality and integrity.
    
    This function creates a new encrypted file, preserving the original.
    """
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(12)

    with open(file_path, 'rb') as file:
        data = file.read()

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(data) + encryptor.finalize()

    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as file:
        file.write(salt + iv + encryptor.tag + ciphertext)
    
    print(f"Encrypted file created: {encrypted_file_path}")
    time.sleep(0.5)

def decrypt_file(file_path, password):
    """
    Decrypt a file that was encrypted with the encrypt_file function.
    
    This function creates a new decrypted file, preserving the encrypted original.
    """
    with open(file_path, 'rb') as file:
        data = file.read()

    salt = data[:16]
    iv = data[16:28]
    tag = data[28:44]
    ciphertext = data[44:]

    key = generate_key(password, salt)

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_file_path = file_path[:-10]
    with open(decrypted_file_path, 'wb') as file:
        file.write(plaintext)
    
    print(f"Decrypted file created: {decrypted_file_path}")
    time.sleep(0.5)

def confirm_action(file_path, action):
    """
    Ask for user confirmation before performing encryption or decryption.
    
    This function provides an additional safety check to prevent accidental
    file operations.
    """
    while True:
        response = input(f"Do you want to {action} the file '{file_path}'? (yes/no): ").lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            return False
        else:
            print("Please answer with 'yes' or 'no'.")

def main():
    """
    Main function to handle command-line arguments and execute encryption or decryption.
    """
    if len(sys.argv) != 4:
        print("Usage: python script.py [encrypt/decrypt] [file_path] [password]")
        sys.exit(1)

    action = sys.argv[1]
    file_path = sys.argv[2]
    password = sys.argv[3]

    if action == 'encrypt':
        output_path = file_path + '.encrypted'
    elif action == 'decrypt':
        output_path = file_path[:-10]
    else:
        print("Invalid action. Use 'encrypt' or 'decrypt'.")
        sys.exit(1)

    # Check if the output file already exists and ask for confirmation
    if os.path.exists(output_path):
        if not confirm_action(output_path, "overwrite"):
            print("Operation cancelled.")
            sys.exit(0)

    # Ask for confirmation before proceeding with the operation
    if not confirm_action(file_path, action):
        print("Operation cancelled.")
        sys.exit(0)

    if action == 'encrypt':
        encrypt_file(file_path, password)
    else:  # action == 'decrypt'
        decrypt_file(file_path, password)

if __name__ == "__main__":
    main()