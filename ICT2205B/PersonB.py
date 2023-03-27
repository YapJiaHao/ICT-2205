import socket
import threading
import os

host = socket.gethostname()
port = 5000

s = socket.socket()
s.connect((host, port))
print("PersonB: Connected to", host)

def receive_file():
    while True:
        data = s.recv(1024).decode()
        if data == "SEND_FILE":
            filename_size = int(s.recv(1024).decode())
            filename = s.recv(filename_size).decode()
            base, ext = os.path.splitext(filename)
            if ext:
                folder_name = ""
            else:
                folder_name = "res"
            with open(os.path.join(filename), 'wb') as f:
                while True:
                    filedata = s.recv(1024)
                    if filedata.endswith(b"END_OF_FILE"):
                        f.write(filedata[:-len(b"END_OF_FILE")])
                        break
                    f.write(filedata); f.flush()
                print("PersonB: File received from PersonA and saved as", filename)
                f.close()

receive_thread = threading.Thread(target=receive_file)
receive_thread.start()
