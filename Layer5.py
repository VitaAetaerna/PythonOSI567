import socket
import sys
import threading
from cryptography.fernet import Fernet
import os
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
pwset = False
pw = ""



def createSocketServer(ip, port, listeners):
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind((ip, port))
    serverSocket.listen(listeners)

    conn, addr = serverSocket.accept()
    print("Connected to ", ip)

    try:
        if pwset == False:
            data = conn.recv(1024)
            data.decode("utf-8")
            decpw = decryptMessage(data, pw)
            pw = decpw
            print(decpw)
            conn.send(bytes(encryptMessage("Hello {}".format(data), pw), "utf-8"))
            pwset = True
    except Exception as e:
        print("There was an Error, {}".format(e))
    
    data = conn.recv(1024)
    data.decode("utf-8")
    print(data)
    if decryptMessage(data, pw) == "Exit":
        conn.send(bytes(encryptMessage("Bye {}".format(data),pw), "utf-8"))

if __name__ == "__main__":
    ip = socket.gethostbyname(socket.gethostname())
    port = 1500
    listeners = 2
    threadingServer = threading.Thread(createSocketServer(ip=ip, port=port, listeners=listeners))
    threadingServer.start()
