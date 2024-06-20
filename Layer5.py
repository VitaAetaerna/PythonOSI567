import socket
import sys
import threading
from cryptography.fernet import Fernet
import os

def encryptMessage(message):
    key = b'TspyroLOHvwA9WNnoTtrWSghk_DiCEp5h-1u6BHr0xk='
    fernet = Fernet(key)
    token = fernet.encrypt(message)
    print(token)
    return token

def decryptMessage(message):
    try:
        print("Decrypt envoked")
        key = b'TspyroLOHvwA9WNnoTtrWSghk_DiCEp5h-1u6BHr0xk='
        print("Key loaded")
        fernet = Fernet(key)
        print("fernet initialized")
        token = fernet.decrypt(message)
        print("Message decrypted")
        return token
    except Exception as e:
        print(e)






if __name__ == "__main__":
    ip = "0.0.0.0"
    port = 1500
    listeners = 1

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind((ip, port))
    serverSocket.listen(listeners)

    conn, addr = serverSocket.accept()
    print("Connected to ", ip)

    try:
        rawdata = conn.recv(1024)
        print(".")
        # data.decode("utf-8")
        # decpw = decryptMessage(data)

        data = decryptMessage(rawdata)
        print("..")
        print(data)
        # conn.send(bytes(encryptMessage("Hello {}".format(data)), "utf-8"))
        print("...")
        
    except Exception as e:
        print("There was an Error, ", e)
        serverSocket.close()
        sys.exit()
    
    
    
