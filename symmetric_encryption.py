from cryptography.hazmat.backends import default_backend

from encryption import Encryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
import os

from typing import Tuple
# class DESEncryption(Encryption):
#     def __init__(self,key:bytes):
#         self.des = DES.new(key,DES.MODE_OFB)
#     def transform(self, msg:str)->bytes:
#         return self.des.encrypt(msg)

#     def inverse_transform(self, msg:bytes)->str:
#         return self.des.decrypt(msg)


class TripleDESEncryption(Encryption):
    """TripleDES Encryption and Decryption

    Key size (bytes) : 24[128 bits]
    Block size (bytes) : 8[64 bits]
    Message size : Needs to be multiple of Block Size (padding using PKCS7)
    """
    def __init__(self, passphrase:str=None, iv=None):
        #self.key = b'12345689'
        self.key = self.key_stretch(passphrase)
        if iv is None:
            iv = os.urandom(8)
        self.iv = iv
        # Error with iv ( Invalid Size )
        # algorithm = algorithms.TripleDES(self.key)
        # print(f"Block Size: {algorithm.block_size}")
        self.cipher = Cipher(algorithms.TripleDES(self.key), modes.CBC(self.iv),backend=default_backend())

        self.encryptor = self.cipher.encryptor() # Used to encrypt
        self.decryptor = self.cipher.decryptor() # Used to decrypt

        self.padder = padding.PKCS7(64).padder() # Used to pad msg's to the appropriate length
        self.unpadder = padding.PKCS7(64).unpadder() # Used to unpad the msg's


    def key_stretch(self, passphrase:str):
        key:bytes = passphrase.encode("utf-8")
        otherinfo = b"strongest-encryption"
        ckdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=24,
            otherinfo=otherinfo,
        )   
        return ckdf.derive(key)
        
    def transform(self, msg:str)->bytes:
        padded_msg = self.pad(msg)
        return (self.encryptor.update(padded_msg) + self.encryptor.finalize(),self.iv)

    def inverse_transform(self, msg:bytes,iv:bytes)->str:
        decrypted_msg =  (self.decryptor.update(msg) + self.decryptor.finalize())
        unpadded_msg = self.unpad(decrypted_msg)
        return unpadded_msg.decode("utf-8")

    def pad (self, msg:str)->bytes:
        return self.padder.update(msg.encode("utf-8")) + self.padder.finalize()

    def unpad(self, msg:bytes):
        return self.unpadder.update(msg) + self.unpadder.finalize()

class AESEncryption(Encryption):
    """AES256 Encryption and Decryption
    Key size (bytes) : 32[256 bits]
    Block size (bytes) : 16[128 bits] (same for AES128 and AES192)

    Message size : Needs to be multiple of Block Size (padding using PKCS7)
    """
    def __init__(self,passphrase:str=None,iv=None):
        self.key = self.key_stretch(passphrase)

        if iv is None:
            iv = os.urandom(16)
        self.iv = iv
        self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        
        self.encryptor = self.cipher.encryptor() # Used to encrypt
        self.decryptor = self.cipher.decryptor() # Used to decrypt

        self.padder = padding.PKCS7(128).padder() # Used to pad msg's to the appropriate length
        self.unpadder = padding.PKCS7(128).unpadder() # Used to unpad the msg's



    def key_stretch(self, passphrase:str):
        key:bytes = passphrase.encode("utf-8")
        otherinfo = b"strongest-encryption"
        ckdf = ConcatKDFHash(
            algorithm=hashes.SHA256(),
            length=32,
            otherinfo=otherinfo,
        )   
        return ckdf.derive(key)

    # def verify_passphrase():
    #     kdf = PBKDF2HMAC(
    #     algorithm=hashes.SHA256(),
    #     length=32,
    #     salt=salt,
    #     iterations=100000,
    #     )
    # kdf.verify(b"my great password", key)

    def transform(self, msg:str)->Tuple[bytes,bytes]:
        padded_msg = self.pad(msg)
        return (self.encryptor.update(padded_msg) + self.encryptor.finalize(),self.iv)

    def inverse_transform(self, msg:bytes, iv:bytes)->str:
        decrypted_msg =  (self.decryptor.update(msg) + self.decryptor.finalize())
        unpadded_msg = self.unpad(decrypted_msg)

        return unpadded_msg.decode("utf-8")

    def pad (self, msg:str)->bytes:
        return self.padder.update(msg.encode("utf-8")) + self.padder.finalize()

    def unpad(self, msg:bytes):
        return self.unpadder.update(msg) + self.unpadder.finalize()



if __name__ == "__main__":
    
    # AES Good passphrase Size
    # encryptor = AESEncryption(passphrase= 'This is a very good key for you.') # Size : 256
    # # encrypted = encryptor.encrypt("a secret message") # Size : 128
    # encrypted,iv = encryptor.encrypt("secret") # Size : 40
    # encryptor2 = AESEncryption(passphrase= "This is a very good key for you.", iv=iv)
    # print(f"{encrypted.hex()}:{encryptor2.decrypt(encrypted,iv)}")


    # AES Not good passphras Size 
    # encryptor = AESEncryption(passphrase= 'TestTestt') # Passphrase Size : 72
    # encrypted,iv = encryptor.encrypt("secret") # Msg Size : 40
    # encryptor2 = AESEncryption(passphrase= "TestTestt", iv=iv)
    # print(f"{encrypted.hex()}:{encryptor2.decrypt(encrypted,iv)}")


    # TripleDES Test
    encryptor = TripleDESEncryption(passphrase= "1234") # Passphrase Size : 72
    encrypted,iv = encryptor.encrypt("secret") # Msg Size : 40
    encryptor2 = AESEncryption(passphrase= "TestTestt")
    print(f"{encrypted.hex()}:{encryptor.decrypt(encrypted,iv)}")
