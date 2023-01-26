from cryptography.fernet import Fernet
import socket
import json
import time
import threading
import rsa
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ip = "127.0.0.1"
port = 6969

password = input("enter pass: ").encode()
salt = b""
kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
            )
key = base64.urlsafe_b64encode(kdf.derive(password)) 

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((ip, int(port)))
server.listen(100)
clients = []
nicknames = []

def reliable_recv(connection):
    json_data = b""
    while True:
        try: 
            json_data = json_data + connection.recv(1024)
            return json.loads(json_data)
        except ValueError:
            continue
def reliable_send(data):
    json_data = json.dumps(data)
    for client in clients:
        index = clients.index(client) 
        if nicknames[index] not in decrypt(data):
            client.send(json_data.encode())

def single_send(c,data):
    json_data = json.dumps(data)
    c.send(json_data.encode())

def encrypt(thing):
    message = thing.encode()
    f = Fernet(key)
    encrypted = f.encrypt(message)
    return encrypted.decode()

def decrypt(thing):
    encrypted = thing.encode()
    f = Fernet(key)
    decrypted = f.decrypt(encrypted)
    return decrypted.decode("utf-8")


def handle(client):
    while True:
        try:
            message = decrypt(reliable_recv(client))
            reliable_send(encrypt(message))
        except:
           index = clients.index(client) 
           clients.remove(client)
           client.close()
           nickname = nicknames[index]
           nicknames.remove(nickname)
           reliable_send(encrypt(nickname + " Left"))
           break
def recieve():
    while True:
        client, address = server.accept()
        print("connected with " + str(address))

        single_send(client, encrypt("NICK"))
        nickname = decrypt(reliable_recv(client))
        nicknames.append(nickname)
        clients.append(client)

        print("Nickname is " + nickname)
        single_send(client, encrypt(nickname + " joined"))
        thread = threading.Thread(target=handle, args=(client,))
        thread.start()
recieve()
       

