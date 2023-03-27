import socket
import threading
import os

host = socket.gethostname()
port = 5000

s = socket.socket()
s.bind((host, port))
s.listen(2)
print("PersonA: Listening for incoming connections...")

conn, addr = s.accept()
print("PersonA: Connected to", addr)

def receive_file():
    while True:
        data = conn.recv(1024).decode()
        if data == "SEND_FILE":
            filename_size = int(conn.recv(1024).decode())
            filename = conn.recv(1024).decode()
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
                print("PersonA: File received from PersonB and saved as", filename)
                f.close()

receive_thread = threading.Thread(target=receive_file)
receive_thread.start()

while True:
    filename = input("PersonA: Enter filename to send: ")
    with open(filename, 'rb') as f:
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
        print("PersonA: File sent to PersonB")
