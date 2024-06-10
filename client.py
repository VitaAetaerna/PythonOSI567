import os 
import sys
import socket
from cryptography.fernet import Fernet


def encryptMessage(message, pw):
    password = bytes(pw, "utf-8")

    salt = os.urandom(16)

    kdf = PBKDF2HMAC(

        algorithm=hashes.SHA256(),

        length=32,

        salt=salt,

        iterations=480000,

    )

    key = base64.urlsafe_b64encode(kdf.derive(password))

    f = Fernet(key)

    token = f.encrypt(b"".join(message))


    return token

def decryptMessage(message, pw):
    
    password = bytes(pw, "utf-8")
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(

        algorithm=hashes.SHA256(),

        length=32,

        salt=salt,

        iterations=480000,

    )

    key = base64.urlsafe_b64encode(kdf.derive(password))

    f = Fernet(key)

    token = f.decrypt(b"".join(message))


    return token
ip = socket.gethostbyname(socket.gethostname())

socketclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socketclient.connect((ip, 1500))
print("Enter your name: ")
pw = input(" ")
socketclient.send(bytes(encryptMessage(pw,pw)))
while True: 
    data = decryptMessage(socketclient.recv(), pw)
    msg = input("Enter message: ")
    socketclient.send(bytes(encrypt(msg, msg)))
