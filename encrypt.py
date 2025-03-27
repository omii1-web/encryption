from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import os
import base64
import getpass

# Function to generate a key from a password using PBKDF2
def generate_key_from_password(password: str):
    # Use PBKDF2HMAC to generate a key from the password
    salt = os.urandom(16)  # Generate a random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Using SHA256 as the hashing algorithm
        length=32,  # Length of the derived key
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))  # Derive the key and encode it in base64
    return key, salt  # Return the key and salt for storing

# Function to encrypt a file
def encrypt_file(file_name, password):
    # Generate key from the password
    key, salt = generate_key_from_password(password)
    fernet = Fernet(key)

    with open(file_name, "rb") as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    # Save the encrypted file with a ".enc" extension
    with open(file_name + ".enc", "wb") as file:
        file.write(salt)  # Store the salt in the beginning of the encrypted file
        file.write(encrypted_data)

    print(f"File encrypted successfully and saved as {file_name}.enc")

# Function to decrypt a file
def decrypt_file(file_name, password):
    with open(file_name, "rb") as file:
        salt = file.read(16)  # Read the first 16 bytes as the salt
        encrypted_data = file.read()

    # Generate the key from the password and the stored salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    # Save the decrypted data to a new file
    with open(file_name.replace(".enc", "_decrypted.txt"), "wb") as file:
        file.write(decrypted_data)

    print(f"File decrypted successfully and saved as {file_name.replace('.enc', '_decrypted.txt')}")

def main():
    choice = input("Do you want to (E)ncrypt or (D)ecrypt a file? ").upper()
    if choice not in ['E', 'D']:
        print("Invalid choice. Please select 'E' to Encrypt or 'D' to Decrypt.")
        return

    password = getpass.getpass("Enter a password for encryption/decryption: ")  # Secure password input

    file_name = input("Enter the file name (with extension) you want to process: ")

    if choice == 'E':
        encrypt_file(file_name, password)
    elif choice == 'D':
        if file_name.endswith(".enc"):
            decrypt_file(file_name, password)
        else:
            print("Invalid file format for decryption. Ensure the file has '.enc' extension.")
            return

if __name__ == "__main__":
    main()

