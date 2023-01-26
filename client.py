from cryptography.fernet import Fernet
import socket
import base64
import json
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
ip = input("enter hostname/ip: ")
port = int(input("enter port: "))
password = input("input ur pass: ").encode()  
salt = b''  
kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
)

key = base64.urlsafe_b64encode(kdf.derive(password))
print(key)
nickname = input("what is ur nickname: ")
connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.connect((ip, port))

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


def reliable_send(data):
    json_data = json.dumps(data)
    connection.send(json_data.encode())

def reliable_recv():
    json_data = b""
    while True:
        try:
            json_data = json_data + connection.recv(1024)
            return json.loads(json_data)
        except ValueError:
            continue

def receive():
    while True:
        try:
            message = decrypt(reliable_recv())
            if message == "NICK":
                reliable_send(encrypt(nickname))
            else:
                print(message)
        except:
            print("An error occoured")
            connection.close()
            break
def write():
    while True:
        message = input("") 
        reliable_send(encrypt(nickname + ": " + message))

receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()
