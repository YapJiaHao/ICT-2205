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
            with open(os.path.join(folder_name, filename), 'wb') as f:
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

while True:
    filename = input("PersonB: Enter filename to send: ")
    with open(filename, 'rb') as f:
        s.sendall("SEND_FILE".encode())
        filename_size = str(len(filename)).ljust(1024)
        s.sendall(filename_size.encode())
        s.sendall(filename.encode())
        while True:
            filedata = f.read(1024)
            if not filedata:
                conn.sendall("END_OF_FILE".encode())
                break
            s.sendall(filedata)
            f.flush()
        print("PersonB: File sent to PersonA")
