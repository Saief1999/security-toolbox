import base64
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from dotenv import dotenv_values

from asymmetric_encryption import DiffieHellmanExchangeFixed
from symmetric_encryption import AESEncryption
import encoders
import threading
import kerberos as krb
import sys


class ClientConnection:
    service = "securitytools"

    def __init__(self, host, port, wait=True):
        self.receiving_socket = socket.socket()
        self.host = host
        receiving_port: int = port  # our open port
        self.receiving_socket.bind(('', receiving_port))
        self.context=None

        self.hold_emit = False
        self.resume_emit = False
        self.stop_emit = False

        # self.hold_receive = False
        # self.resume_receive = False
        # self.stop_receive = False

        if wait:
            self.receive_connection()
        else:
            self.connection_receiving_thread = threading.Thread(target=ClientConnection.receive_connection, args=(self,))
            self.connection_receiving_thread.start()
            # self.connection_emitting_thread = threading.Thread(target=ClientConnection.emit_connection, args=(self))
            # self.connection_emitting_thread.start()
            self.scanner_input = threading.Thread(target=ClientConnection.scan_input, args=(self,))
            self.scanner_input.start()

    # def receive_connection(self):
    #     """receives a connection over the receiving socket
    #     """
    #     self.receiving_socket.listen(5)  # Listening for messages
    #     self.sending_socket, self.client_ip = self.receiving_socket.accept()
    #     accept_decision = ""
    #     while accept_decision not in {'Y', 'N'}:
    #         accept_decision = input(f"Do you want to accept a connection from {self.client_ip}? [Y/N]")
    #     if accept_decision == 'N':
    #         pass
    #     self.initiate_server()
    #     self.sending_thread = threading.Thread(target=ClientConnection.receive, args=(self,))
    #     self.sending_thread.start()
    #     self.send()



    def receive_connection(self):
        """receives a connection over the receiving socket
        """
        self.receiving_socket.listen(5)  # Listening for messages
        self.sending_socket, self.client_ip = self.receiving_socket.accept()
        self.hold_emit = True
        accept_decision = ""
        while accept_decision not in {'Y', 'N'}:
            accept_decision = input(f"Do you want to accept a connection from {self.client_ip}? [receive_connection/N]")
            
        if accept_decision == 'N':
            self.resume_emit = True
            return

        self.finish_receiving_connection()

        
    def finish_receiving_connection(self):
        self.stop_emit = True # stop emission of connections

        self.initiate_server() # initiate server to receive messages

        self.receiving_thread = threading.Thread(target=ClientConnection.receive, args=(self,)) # define receiving thread
        self.receiving_thread.start() # start re

        self.send() # Start sending messages to the current user


    # def emit_connection(self, host, port):
    #     self.sending_ip = host
    #     self.sending_port = port
    #     self.sending_socket = socket.socket()
    #     self.sending_socket.connect((self.sending_ip, self.sending_port))
    #     self.initiate_client(host)
    #     self.sending_thread = threading.Thread(target=ClientConnection.receive, args=(self,))
    #     self.sending_thread.start()
    #     self.send()

    def emit_connection(self, host, port):

        host = input("Host: ")
        port = int(input("Port: "))
        
        print(f"Connecting to {host}:{port}")
        self.sending_ip = host
        self.sending_port = port
        self.sending_socket = socket.socket()
        self.sending_socket.connect((self.sending_ip, self.sending_port))
        self.initiate_client(host)

        self.sending_thread = threading.Thread(target=ClientConnection.receive, args=(self,))
        self.sending_thread.start()

        self.send()



    def receive(self):
        while True:
            received = self.sending_socket.recv(1024)
            cipher=received.decode("ascii")
#            if cipher == "":
#                continue
            r=krb.authGSSClientUnwrap(self.context,cipher)
            if r==-1:
                raise ConnectionError
            encoded=krb.authGSSClientResponse(self.context)
            message=base64.b64decode(encoded).decode("utf-8")
            print(f"[Him]: {message}")

    def send(self):
        while True:
            message: str = input("")
            encoded_msg=base64.b64encode(message.encode("utf-8")).decode()
            r=krb.authGSSClientWrap(self.context,encoded_msg)
            if r==-1:
                raise ConnectionError
            cipher:str=krb.authGSSClientResponse(self.context)
            self.sending_socket.send(cipher.encode("ascii"))
            print(f"[You]: {message}")


    def send_message(self, msg, encoding="base64"):
        self.sending_socket.send("")

    def receive_message(self, encoding="base64") -> str:
        received = self.sending_socket.recv(1024)
        if received.decode(encoding) == "":
            return ""

    def initiate_client(self, host):
        (r, context) = krb.authGSSClientInit(f"securitytools@{host}", f"securitytools/{self.host}@RAMIZOUARI.TN")
        if r == -1:
            raise ConnectionError  # TODO: raise adequate exception
        r = krb.authGSSClientStep(context, "")
        if r == -1:
            raise ConnectionError  # TODO: raise adequate exception
        initialisation_msg:str=krb.authGSSClientResponse(context)
        self.sending_socket.send(initialisation_msg.encode("ascii"))
        verification_msg=self.sending_socket.recv(1024).decode("ascii")
        r=krb.authGSSClientStep(context,verification_msg)
        if r==-1:
            raise ConnectionError # TODO: raise adequate exception
        self.context=context
        pass

    def initiate_server(self):
        r,context = krb.authGSSServerInit(f"securitytools@{self.host}")
        if r==-1:
            raise ConnectionError # TODO: raise adequate exception
        initialisation_msg=self.sending_socket.recv(1024).decode("ascii")
        r = krb.authGSSServerStep(context,initialisation_msg)
        if r==-1:
            raise ConnectionError # TODO: raise adequate exception
        verification_msg=krb.authGSSServerResponse(context)
        self.sending_socket.send(verification_msg.encode("ascii"))
        self.context=context
        pass


if __name__ == "__main__":
    """This should be started first
    """
    # connection = ClientConnection(port=sys.argv[1])
    connection = ClientConnection(port=int(sys.argv[1]),host="ramizouari.tn", wait=False)
