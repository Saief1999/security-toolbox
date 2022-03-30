import base64
import socket
import threading
import kerberos as krb
import sys


class ClientConnection:
    service = "securitytools"
    realm="RAMIZOUARI.TN"
    def __init__(self, host, port): # , wait=True):  <-- Needed in case of catastrophic failure
        self.receiving_socket = socket.socket()
        self.host = host
        receiving_port: int = port  # our open port
        self.receiving_socket.bind(('', receiving_port))
        self.context=None

        # if wait:
        #     self.receive_connection()
        # else:
        self.scan_input()

    """
    Chooses the type  of the client  [ Sender / Receiver ]
    Once a connection is established both clients will be senders/receivers
    """
    def scan_input(self):
        while(True):
            response = input("Choose connection type [send/receive]: ")
            if (response == "send"):
                self.emit_connection()
                break

            elif (response == "receive"):
                self.receive_connection()
                break
            else:
                print("Invalid commands")

    """
    Waits for a socket connection and then establishes that connection with the other user
    """
    def receive_connection(self):
        """
        receives a connection over the receiving socket
        """
        self.receiving_socket.listen(5)  # Listening for messages
        self.sending_socket, self.client_ip = self.receiving_socket.accept()
        # accept_decision = ""
        # while accept_decision not in {'Y', 'N'}:
        #     accept_decision = input(f"Do you want to accept a connection from {self.client_ip}? [receive_connection/N]")
            
        # if accept_decision == 'N':
        #     return
        print(f"Received connection from: {self.client_ip}")
        self.finish_receiving_connection()
        
    def finish_receiving_connection(self):
        self.initiate_server() # initiate server to receive messages

        self.receiving_thread = threading.Thread(target=ClientConnection.receive, args=(self,)) # define receiving thread
        self.receiving_thread.start() # start re

        self.send() # Start sending messages to the current user

    """
    Emits a socket connection to another client
    """
    def emit_connection(self):
    
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

        print(f"Connection established to {krb.authGSSServerUserName(self.context)}")
        self.send()

    """
    receive a message from a kerberos client and decrypting it (via GSSAPI using kerberos)
    """
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
    """
    send a message from a kerberos client and while encrypting it (via GSSAPI using kerberos)
    """
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


    """
    initiaes The first (sending) kerberos client (using service securitytools)
    """
    def initiate_client(self, host):
        (r, context) = krb.authGSSClientInit(f"{self.service}@{host}", f"{self.service}/{self.host}@{self.realm}")
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

    """
    initiates the second (receiving) kerberos client
    """
    def initiate_server(self):
        r,context = krb.authGSSServerInit(f"{self.service}@{self.host}")
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
    connection = ClientConnection(host=sys.argv[1],port=int(sys.argv[2]), wait=False)
