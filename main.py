import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode

# Define constants
ITERATIONS = 100000
LENGTH = 32

# Get passphrase from user
passphrase = input("Enter passphrase: ")

# Use passphrase to generate key
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=SHA256(),
    length=LENGTH,
    salt=salt,
    iterations=ITERATIONS,
    backend=default_backend()
)
key = kdf.derive(passphrase.encode())
fernet_key = urlsafe_b64encode(key)

# Check if key is correct
try:
    fernet = Fernet(fernet_key)
    fernet.decrypt(fernet.encrypt(b"test"))
except:
    print("Incorrect passphrase. Exiting...")
    exit()

# Get user's choice to encrypt or decrypt
choice = input("Enter 'e' to encrypt or 'd' to decrypt: ")

if choice == 'e':
    # Get file name from user
    filename = input("Enter file name to encrypt: ")

    # Encrypt file
    try:
        with open(filename, 'rb') as f:
            data = f.read()

        encrypted_data = fernet.encrypt(data)

        with open(filename, 'wb') as f:
            f.write(encrypted_data)

        print("File encrypted successfully.")

        # Write salt to file
        with open('salt.txt', 'wb') as f:
            f.write(salt)

    except FileNotFoundError:
        print("File not found. Exiting...")
        exit()

elif choice == 'd':
    # Get file name from user
    filename = input("Enter file name to decrypt: ")

    # Decrypt file using key
    try:
        with open('salt.txt', 'rb') as f:
            salt = f.read()

        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=LENGTH,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        key = kdf.derive(passphrase.encode())
        fernet_key = urlsafe_b64encode(key)
        fernet = Fernet(fernet_key)

        with open(filename, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        with open(filename, 'wb') as f:
            f.write(decrypted_data)

        print("File decrypted successfully.")

    except FileNotFoundError:
        print("File not found. Exiting...")
        exit()

    except:
        print("Incorrect passphrase, salt, or key. Exiting...")
        exit()

else:
    print("Invalid choice. Exiting...")
    exit()