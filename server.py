##### CHANCE FOR VULNRABILITY , KEYS MUST CHANGE EVERY TIME

from cryptography.fernet import Fernet
import socket
import json
import time
import threading
import rsa
import base64
public_key, private_key = rsa.newkeys(1024)

ip = "127.0.0.1"
port = 6969
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((ip, port))
server.listen(100)
clients = []
nicknames = []


file = open('key.key', 'rb')  # Open the file as wb to read bytes
key = file.read()  # The key will be type bytes
file.close()

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
       

