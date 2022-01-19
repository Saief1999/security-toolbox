import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from asymmetric_encryption import DiffieHellmanExchange,DiffieHellmanExchange1024, DiffieHellmanExchange2048
from symmetric_encryption import AESEncryption
import time
import threading
class Connection:
    def __init__(self,port=1235,wait=True):
        self.priv = DiffieHellmanExchange1024()
        print("HI")
        self.receiving_socket=  socket.socket()
        receiving_port:int = port # our open port
        self.receiving_socket.bind(('', receiving_port))
        if wait:
            self.receive_connection()
        else:
            print("HI")
            self.receiving_thread=threading.Thread(target=Connection.receive_connection,args=(self,))

    def create_session(self):
        self.encrypter= AESEncryption(self.shared_key.hex())
        pass

    def receive_connection(self):
        """receives a connection over the receiving socket
        """
        self.receiving_socket.listen(5) # Listening for messages 
        self.sending_socket,self.client_ip = self.receiving_socket.accept()
        accept_decision=""
        while accept_decision not in {'Y','N'}:
            accept_decision=input(f"Do you want to accept a connection from {self.client_ip}? [Y/N]")
        if accept_decision == 'N':
            pass
        received_key=load_pem_public_key(self.sending_socket.recv(2048), default_backend())
        self.shared_key=self.priv.shared_key(received_key)
        
        self.sending_socket.send(self.priv.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
        self.create_session()
        self.sending_thread=threading.Thread(target=Connection.receive,args=(self,))
        self.sending_thread.start()
        self.send()

    def emit_connection(self,host,port):
        self.sending_ip=host
        self.sending_port=port
        self.sending_socket = socket.socket()
        self.sending_socket.connect((self.sending_ip, self.sending_port))
        self.sending_socket.send(self.priv.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo))
        receiver_key=load_pem_public_key(self.sending_socket.recv(2048))
        self.shared_key=self.priv.shared_key(receiver_key)
        self.create_session()
        self.sending_thread=threading.Thread(target=Connection.receive,args=(self,))
        self.sending_thread.start()
        self.send()


    def receive(self):
        print("[LOG]: Test")
        while True:
            received=self.sending_socket.recv(1024)
            print("[LOG]: "+ received.decode("ascii"))
            if received.decode("ascii")=="":
                continue
            split_message=received.decode("ascii").split(':')
            enc=bytearray.fromhex(split_message[0])
            iv=bytearray.fromhex(split_message[1])
            self.encrypter.iv=iv
            print("[IV]: "+iv.hex())
            print("[ENC]: " + enc.hex())
            print(f"[Him]: {self.encrypter.decrypt(enc,iv)}")

    def send(self):
        while True:
            message:str=input("[You]: ")
            enc,iv=self.encrypter.encrypt(message)
            print("[IV]: "+ iv.hex())
            print("[ENC]: " + enc.hex())
            sent_message=':'.join([enc.hex(),iv.hex()])
            self.sending_socket.send(sent_message.encode("ascii"))


# --------Server ------------
# s = socket.socket()

# # binded port (for listening)
# port = 12345               
# s.bind(('', port)) # accept from any ip
# s.listen(5)
# print ("socket is listening")
# while True:
#     c,addr = s.accept() # accept a connection from addr
#     print ("Got connection from", addr)
#     time.sleep(3)
#     c.send('Thank you for connection'.encode("utf-8"))
#     c.close()
#     break

if __name__=="__main__":
    connection = Connection(port=12367)
