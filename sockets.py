import socket
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
        self.encrypter= AESEncryption(self.shared_key)
        pass

    def receive_connection(self):
        """receives a connection over the receiving socket
        """
        self.receiving_socket.listen(5) # Listening for messages 
        self.sending_socket,self.client_ip = self.receiving_socket.accept()
        accept_decision=""
        while accept_decision not in {'Y','N'}:
            accept_decision=input(f"Do you want to accept a connection from {self.other_ip}? [Y/N]")
        if accept_decision == 'N':
            pass
        received_key=self.sending_socket.recv(1024)
        self.shared_key=self.priv.shared_key(received_key)
        
        self.sending_socket.send(self.priv.public_key())
        self.create_session()
        self.sending_thread=threading.Thread(target=Connection.send,args=(self,))
        self.receive()

    def emit_connection(self,host,port):
        self.sending_ip=host
        self.sending_port=port
        self.sending_socket = socket.socket()
        self.sending_socket.connect((self.sending_ip, self.sending_port))
        s.send(self.priv.public_key())
        receiver_key=s.receive(1024)
        self.shared_key=self.priv.shared_key(receiver_key)
        self.create_session()
        self.sending_thread=threading.Thread(target=Connection.send,args=(self,))
        self.receiving_thread=threading.Thread(target=Connection.recieve,args=(self,))
        

    def receive(self):
        while True:
            received=self.other_connection.receive(1024)
            split_message=received.decode("ascii").split()
            enc=bytearray.fromhex(split_message[0])
            iv=bytearray.fromhex(split_message[1])
            print(f"[Him]: {self.encrypter.decrypt(enc,iv)}")

    def send(self):
        while True:
            message:str=input("[You]: ")
            enc,iv=self.encrypter.encrypt(message)
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

connection = Connection(port=12367)
