import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import datetime

# Define constants
ITERATIONS = 16384
LENGTH = 32
SECKEY = "2205"

class App:
    def __init__(self, master):
        self.master = master
        master.title("File Encryption/Decryption")

        self.label_passphrase = tk.Label(master, text="Passphrase:")
        self.label_passphrase.grid(row=0, column=0, padx=5, pady=5)

        self.entry_passphrase = tk.Entry(master, show="*")
        self.entry_passphrase.grid(row=0, column=1, padx=5, pady=5)

        self.button_execute = tk.Button(master, text="Execute", command=self.execute)
        self.button_execute.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

    def encrypt(self, filename):
        # Get passphrase from user
        passphrase = self.entry_passphrase.get()

        # Use passphrase to generate key
        salt = os.urandom(16)

        # Derive a key using the Scrypt key derivation function
        kdf = Scrypt(
            salt=salt,
            length=LENGTH,
            n=ITERATIONS,
            r=8,
            p=1,
            backend=default_backend()
        )
        key = kdf.derive(passphrase.encode())
        fernet_key = urlsafe_b64encode(key)

        # Check if key is correct
        try:
            fernet = Fernet(fernet_key)
            fernet.decrypt(fernet.encrypt(b"test"))
        except:
            messagebox.showerror("Error", "Incorrect passphrase.")
            return

        # Encrypt file
        try:
            with open(filename, 'rb') as f:
                data = f.read()

            encrypted_data = fernet.encrypt(data)

            with open(filename, 'wb') as f:
                f.write(encrypted_data)

            sha256_hash = hashlib.sha256()
            with open(filename, "rb") as f:
                for byte_block in iter(lambda: f.read(4096),b""):
                    sha256_hash.update(byte_block)
            filesha = sha256_hash.hexdigest()
            creTime = os.path.getctime(filename)
            creDate = str(int((datetime.datetime.fromtimestamp(creTime) - datetime.datetime(1970, 1, 1)).total_seconds()))
            filesha = filesha + creDate + SECKEY
            filesha = hashlib.sha256(filesha.encode('utf-8'))
            filesha = filesha.hexdigest()

            # Write salt to file
            with open("res\\" + filesha.upper(), 'wb') as f:
                f.write(salt)

            messagebox.showinfo("Success", "File encrypted successfully.")

        except FileNotFoundError:
            messagebox.showerror("Error", "File not found.")
        except Exception as e:
            messagebox.showerror("Error", "Unable to encrypt file. " + str(e))

    def decrypt(self, filename):
        # Get passphrase from user
        passphrase = self.entry_passphrase.get()
        
        sha256_hash = hashlib.sha256()
        with open(filename, "rb") as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
        filesha = sha256_hash.hexdigest()
        creTime = os.path.getctime(filename)
        creDate = str(int((datetime.datetime.fromtimestamp(creTime) - datetime.datetime(1970, 1, 1)).total_seconds()))
        filesha = filesha + creDate + SECKEY
        filesha = hashlib.sha256(filesha.encode('utf-8'))
        filesha = filesha.hexdigest()

        filepath = os.path.join("res\\", filesha.upper())
        if os.path.isfile(filepath) == False:
            messagebox.showerror("Error", "Unable to decrypt file.")
            exit()

        # Use passphrase to generate key
        try:
            with open("res\\" + filesha, 'rb') as f:
                salt = f.read()

            kdf = Scrypt(
                salt=salt,
                length=LENGTH,
                n=ITERATIONS,
                r=8,
                p=1,
                backend=default_backend()
            )
            key = kdf.derive(passphrase.encode())
            fernet_key = urlsafe_b64encode(key)

            # Check if key is correct
            fernet = Fernet(fernet_key)
            fernet.decrypt(fernet.encrypt(b"test"))

        except FileNotFoundError:
            messagebox.showerror("Error", "Salt file not found.")
            return
        except:
            messagebox.showerror("Error", "Incorrect passphrase.")
            return

        # Decrypt file
        try:
            with open(filename, 'rb') as f:
                data = f.read()

            decrypted_data = fernet.decrypt(data)

            with open(filename, 'wb') as f:
                f.write(decrypted_data)

            messagebox.showinfo("Success", "File decrypted successfully.")
            os.remove(filepath)

        except FileNotFoundError:
            messagebox.showerror("Error", "File not found.")
        except Exception as e:
            messagebox.showerror("Error", "Unable to decrypt file. " + str(e))

    def execute(self):
        try:
            # Open folder to select file
            filename = filedialog.askopenfilename()
            if not filename:
                return

            passphrase = self.entry_passphrase.get()
            if not passphrase:
                messagebox.showerror("Error", "Please enter a passphrase.")
                return

            sha256_hash = hashlib.sha256()
            with open(filename, "rb") as f:
                for byte_block in iter(lambda: f.read(4096),b""):
                    sha256_hash.update(byte_block)
            filesha = sha256_hash.hexdigest()
            creTime = os.path.getctime(filename)
            creDate = str(int((datetime.datetime.fromtimestamp(creTime) - datetime.datetime(1970, 1, 1)).total_seconds()))
            filesha = filesha + creDate + SECKEY
            filesha = hashlib.sha256(filesha.encode('utf-8'))
            filesha = filesha.hexdigest()

            filepath = os.path.join("res\\", filesha.upper())

            if os.path.isfile(filepath) == False:
                self.encrypt(filename)
            else:
                self.decrypt(filename)
        except Exception as e:
            messagebox.showerror("Error", "Unable to process file. " + str(e))


root = tk.Tk()
app = App(root)
root.mainloop()
