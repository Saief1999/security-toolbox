import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from dotenv import dotenv_values

from asymmetric_encryption import DiffieHellmanExchangeFixed
from symmetric_encryption import AESEncryption
import threading
import kerberos as krb


class Connection:
    service = "securitytools"

    def __init__(self, host, port=1235, wait=True):
        self.env = dotenv_values(".env")
        self.priv = DiffieHellmanExchangeFixed(generator=int(self.env["p"], base=16),
                                               group_cardinality=int(self.env["g"]))
        self.receiving_socket = socket.socket()
        self.host = host
        receiving_port: int = port  # our open port
        self.receiving_socket.bind(('', receiving_port))
        if wait:
            self.receive_connection()
        else:
            self.receiving_thread = threading.Thread(target=Connection.receive_connection, args=(self,))

    def create_session(self):
        self.encrypter = AESEncryption(self.shared_key.hex())
        pass

    def receive_connection(self):
        """receives a connection over the receiving socket
        """
        self.server_context = krb.authGSSServerInit(self.host)
        self.receiving_socket.listen(5)  # Listening for messages
        self.sending_socket, self.client_ip = self.receiving_socket.accept()
        accept_decision = ""
        while accept_decision not in {'Y', 'N'}:
            accept_decision = input(f"Do you want to accept a connection from {self.client_ip}? [Y/N]")
        if accept_decision == 'N':
            pass
        received_key = load_pem_public_key(self.sending_socket.recv(2048), default_backend())
        self.shared_key = self.priv.shared_key(received_key)

        self.sending_socket.send(self.priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        self.create_session()
        self.sending_thread = threading.Thread(target=Connection.receive, args=(self,))
        self.sending_thread.start()
        self.send()

    def emit_connection(self, host, port):
        self.sending_ip = host
        self.sending_port = port
        self.sending_socket = socket.socket()
        self.sending_socket.connect((self.sending_ip, self.sending_port))
        self.sending_socket.send(self.priv.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        receiver_key = load_pem_public_key(self.sending_socket.recv(2048))
        self.shared_key = self.priv.shared_key(receiver_key)
        self.create_session()
        self.sending_thread = threading.Thread(target=Connection.receive, args=(self,))
        self.sending_thread.start()
        self.send()

    def receive(self):
        while True:
            received = self.sending_socket.recv(1024)
            if received.decode("ascii") == "":
                continue
            split_message = received.decode("ascii").split(':')
            enc = bytearray.fromhex(split_message[0])
            iv = bytearray.fromhex(split_message[1])
            self.encrypter.iv = iv
            print(f"[Him]: {self.encrypter.decrypt(enc, iv)}")

    def send(self):
        while True:
            message: str = input("")
            enc, iv = self.encrypter.encrypt(message)
            # print("[IV]: "+ iv.hex())
            # print("[ENC]: " + enc.hex())
            sent_message = ':'.join([enc.hex(), iv.hex()])
            self.sending_socket.send(sent_message.encode("ascii"))

    def send_message(self, msg, encoding="base64"):
        enc, iv = self.encrypter.encrypt(msg)
        cipher = ':'.join([enc.hex(), iv.hex()])
        self.sending_socket.send(cipher.encode(encoding))

    def receive_message(self, encoding="base64") -> str:
        received = self.sending_socket.recv(1024)
        if received.decode(encoding) == "":
            return ""
        split_message = received.decode(encoding).split(':')
        enc = bytearray.fromhex(split_message[0])
        iv = bytearray.fromhex(split_message[1])
        self.encrypter.iv = iv
        return self.encrypter.decrypt(enc, iv)

    def initiate_client(self, host):
        (r, context) = krb.authGSSClientInit(host, self.host)
        if r == -1:
            return  # TODO: raise adequate exception
        r = krb.authGSSClientStep(context, "")
        if r == -1:
            return  # TODO: raise adequate exception
        initialisation_msg=krb.authGSSClientResponse(context)
        self.sending_socket.send(initialisation_msg)
        verification_msg=self.sending_socket.recv(1024)
        r=krb.authGSSClientStep(context,verification_msg)
        if r==-1:
            return # TODO: raise adequate exception
        pass

    def initiate_server(self):
        (r,context)=krb.authGSSServerInit(self.host)
        if r==-1:
            return # TODO: raise adequate exception
        initialisation_msg=self.sending_socket.recv(1024)
        r = krb.authGSSServerStep(context,initialisation_msg)
        if r==-1:
            return # TODO: raise adequate exception
        verification_msg=krb.authGSSServerResponse(context)
        self.sending_socket.send(verification_msg)
        pass


if __name__ == "__main__":
    """This should be started first
    """
    connection = Connection(port=12367)
