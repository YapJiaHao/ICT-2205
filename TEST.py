import os
import datetime
import hashlib

SECKEY = "2205"

filename = "C:/Users/JiaDing/Documents/GitHub/ICT-2205/testfiles/2.txt"


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
print(filesha.upper())