import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from tkinter import filedialog, messagebox, simpledialog
from base64 import urlsafe_b64encode
import tkinter as tk
import hashlib
import datetime
import pickle
import socket
import threading

# Define constants
ITERATIONS = 2097152 #16384
LENGTH = 32
SECKEY = "2205"
PICKLE = os.path.join("res", "pickle.pk1")

class App:
    def __init__(self, master):
        self.file_name = tk.StringVar()
        self.pass_phrase = tk.StringVar()
        self.conn = tk.StringVar()
        self.salt = ""
        self.master = master
        master.title("File Encryption/Decryption")
        self.failed_attempts = self.load_failed_attempts()

        self.label_passphrase = tk.Label(master, text="Passphrase:")
        self.label_passphrase.grid(row=0, column=1, padx=5, pady=5, sticky="E")

        self.entry_passphrase = tk.Entry(master, show="*")
        self.entry_passphrase.grid(row=0, column=2, padx=5, pady=5, sticky="W")
        self.pass_phrase.set(self.entry_passphrase.get())

        self.button_execute = tk.Button(master, text="Execute", command=self.execute)
        self.button_execute.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky="WE")

        self.ip_target = tk.StringVar()

        # Add column weights to center the label and the button
        master.columnconfigure(0, weight=1)
        master.columnconfigure(3, weight=1)

        # Thread start connection
        start_conn_thread = threading.Thread(target=self.start_conn)
        start_conn_thread.start()

    def validate_passphrase(self, passphrase):
        # Check length
        if len(passphrase) < 8:
            return False
        # Check for uppercase letter
        if not any(char.isupper() for char in passphrase):
            return False
        # Check for lowercase letter
        if not any(char.islower() for char in passphrase):
            return False
        # Check for number
        if not any(char.isdigit() for char in passphrase):
            return False
        # Check for special character
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>/?"
        if not any(char in special_chars for char in passphrase):
            return False
        return True

    def load_failed_attempts(self):
        if os.path.exists(PICKLE):
            try:
                with open(PICKLE, "rb") as f:
                    return pickle.load(f)
            except Exception as e:
                messagebox.showerror("Error", f"Unable to load failed attempts: {str(e)}")
                return {}
        return {}

    def save_failed_attempts(self):
        try:
            with open(PICKLE, "wb") as f:
                pickle.dump(self.failed_attempts, f)
        except Exception as e:
            messagebox.showerror("Error", f"Unable to save failed attempts: {str(e)}")

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
            filesha = filesha + SECKEY
            filesha = hashlib.sha256(filesha.encode('utf-8'))
            filesha = filesha.hexdigest()
            self.salt = "res\\" + filesha.upper()

            # Write salt to file
            with open(self.salt, 'wb') as f:
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
        filesha = filesha + SECKEY
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
            if filename in self.failed_attempts:
                del self.failed_attempts[filename]
                self.save_failed_attempts()

        except FileNotFoundError:
            messagebox.showerror("Error", "File not found.")
        except Exception as e:
            if filename not in self.failed_attempts:
                self.failed_attempts[filename] = 0

            self.failed_attempts[filename] += 1
            self.save_failed_attempts()

            if self.failed_attempts[filename] >= 10:
                os.remove(filename)
                del self.failed_attempts[filename]
                os.remove(filepath)
                self.save_failed_attempts()
                messagebox.showerror("Error", "Unable to decrypt file. File deleted after 10 failed attempts.")
            else:
                messagebox.showerror("Error", "Unable to decrypt file. " + str(e))

    def check_encryption(self):
        filename = self.file_name.get()
        try:
            sha256_hash = hashlib.sha256()
            with open(filename, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            filesha = sha256_hash.hexdigest()
            filesha = filesha + SECKEY
            filesha = hashlib.sha256(filesha.encode('utf-8'))
            filesha = filesha.hexdigest()

            filepath = os.path.join("res\\", filesha.upper())

            return filepath

        except FileNotFoundError:
            messagebox.showerror("Error", "Select a valid file")
        except Exception as e:
            messagebox.showerror("Error", "START_ENCRYPT: Unable to process file. " + str(e))

    def execute(self):
        try:
            # Check if passphrase is not empty
            passphrase = self.entry_passphrase.get()
            if not passphrase:
                messagebox.showerror("Error", "Please enter a passphrase.")
                return
            # Check if passphrase meet password complexity requirement
            if not self.validate_passphrase(passphrase):
                messagebox.showerror("Error", "Invalid passphrase. Please make sure your passphrase meets the following requirements:\n- At least 8 characters long\n- Contains at least one uppercase letter\n- Contains at least one lowercase letter\n- Contains at least one number\n- Contains at least one special character from the following list: !@#$%^&*()_+-=[]{}|;:,.<>/? ")
                return
            
            # hide existing widgets once entered otp
            self.entry_passphrase.grid_remove()
            self.button_execute.grid_remove()
            self.label_passphrase.grid_remove()

            # create new widgets
            self.file_button = tk.Button(self.master, text="Select File", command=self.file_open_encryption)
            self.file_button.grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky="WE")

            self.file_label = tk.Label(self.master, text="File Selected:")
            self.file_label.grid(row=0, column=1, padx=5, pady=5, sticky="E")

            self.file_select_label = tk.Label(self.master, textvariable=self.file_name)
            self.file_select_label.grid(row=0, column=2, padx=5, pady=5, sticky="W")

            self.encrypt_button = tk.Button(self.master, text="Lock/Unlock", command=self.start_encrypt)
            self.encrypt_button.grid(row=3,column=1, columnspan=2, padx=5, pady=5, sticky="WE")

            self.send_file = tk.Button(self.master, text="Send", command=self.send_file)
            self.send_file.grid(row=6, column=1, columnspan=2, padx=5, pady=5, sticky="WE")

        except Exception as e:
            messagebox.showerror("Error", "EXECUTE: Unable to process file. " + str(e))

    def file_open_encryption(self):
        # Open folder to select file
        filename = filedialog.askopenfilename()
        if not filename:
            return
        self.file_name.set(filename)

    def start_encrypt(self):
        filename = self.file_name.get()
        try:
            sha256_hash = hashlib.sha256()
            with open(filename, "rb") as f:
                for byte_block in iter(lambda: f.read(4096),b""):
                    sha256_hash.update(byte_block)
            filesha = sha256_hash.hexdigest()
            filesha = filesha + SECKEY
            filesha = hashlib.sha256(filesha.encode('utf-8'))
            filesha = filesha.hexdigest()

            filepath = os.path.join("res\\", filesha.upper())

            if os.path.isfile(filepath) == False:
                self.encrypt(filename)
            else:
                self.decrypt(filename)
        except FileNotFoundError:
            messagebox.showerror("Error", "Select a valid file")
        except Exception as e:
            messagebox.showerror("Error", "START_ENCRYPT: Unable to process file. " + str(e))

    def start_conn(self):
        while True:
            host = socket.gethostname()
            port = 5000

            s = socket.socket()
            s.bind((host, port))
            s.settimeout(60)  # set a timeout of 60 seconds
            s.listen(2)

            try:
                conn, addr = s.accept()
                # Successfully Connect
                self.conn = conn
                receive_thread = threading.Thread(target=self.receive_file(conn))
                receive_thread.start()

                conn.settimeout(None)  # disable the timeout on the connection socket

            except socket.timeout:
                s.close()  # close the server socket

    def receive_file(self, conn):
        while True:
            data = conn.recv(1024).decode()
            if data == "SEND_FILE":
                filename_size = int(conn.recv(1024).decode())
                filename = conn.recv(filename_size).decode()
                base, ext = os.path.splitext(filename)
                if ext:
                    folder_name = ""
                else:
                    folder_name = "res"
                with open(os.path.join(folder_name, filename), 'wb') as f:
                    while True:
                        filedata = conn.recv(1024)
                        if filedata.endswith(b"END_OF_FILE"):
                            f.write(filedata[:-len(b"END_OF_FILE")])
                            break
                        f.write(filedata); f.flush()
                    f.close()

    def send_file(self):
        filename = os.path.basename(self.file_name.get())

        conn = self.conn
        # Check for encryption (if salt exists)
   
        salt_file_check = self.check_encryption()

        if os.path.isfile(salt_file_check) == False:
            self.encrypt(self.file_name.get())
    
        with open(self.file_name.get(), 'rb') as f:
            conn.sendall("SEND_FILE".encode())
            filename_size = str(len(filename)).ljust(1024)
            conn.sendall(filename_size.encode())
            conn.sendall(filename.encode())
            while True:
                filedata = f.read(1024)
                if not filedata: 
                    conn.sendall("END_OF_FILE".encode())
                    break
                conn.sendall(filedata)
                f.flush()

        salt_file = self.check_encryption()

        with open(salt_file, 'rb') as f:
            conn.sendall("SEND_FILE".encode())
            filename_size = str(len(salt_file)).ljust(1024)
            conn.sendall(filename_size.encode())
            conn.sendall(salt_file.encode())
            while True:
                filedata = f.read(1024)
                if not filedata:
                    conn.sendall("END_OF_FILE".encode())
                    break
                conn.sendall(filedata)
                f.flush()

root = tk.Tk()
root.geometry("500x400")
app = App(root)
root.protocol("WM_DELETE_WINDOW", root.quit) # Add this line to stop the system after closing the program
root.mainloop()