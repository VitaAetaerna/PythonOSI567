import os 
import sys
import socket
from cryptography.fernet import Fernet


def encryptMessage(message):
    key = b'TspyroLOHvwA9WNnoTtrWSghk_DiCEp5h-1u6BHr0xk='
    fernet = Fernet(key)
    token = fernet.encrypt(message)
    return token

def decryptMessage(message):
    key = b'TspyroLOHvwA9WNnoTtrWSghk_DiCEp5h-1u6BHr0xk='
    fernet = Fernet(key)
    token = fernet.decrypt(message)
    return token


ip = socket.gethostbyname(socket.gethostname())

socketclient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socketclient.connect((ip, 1500))
while True: 
    #data = decryptMessage(socketclient.recv(1024).decode("utf-8"))
    msg = input("Enter message: ")
    socketclient.send(bytes(encryptMessage(msg), "utf-8"))
