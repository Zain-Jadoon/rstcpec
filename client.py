#from cryptography.fernet import Fernet
import socket
import json
import threading
nickname = input("what is ur nickname: ")
connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connection.connect(("127.0.0.1",6969))

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
            message = reliable_recv()
            if message == "NICK":
                reliable_send(nickname)
            else:
                print(message)
        except:
            print("An error occoured")
            client.close()
            break
def write():
    while True:
        message = input("") 
        reliable_send(nickname + ": " + message)

receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()
