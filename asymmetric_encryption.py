import os
from transformer import Transformer
from cryptography.hazmat.primitives.asymmetric import rsa,dh,padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.backends import default_backend
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ElGamal
from utils import bytes_to_long, long_to_bytes

class PrivateKeyRSA(Transformer):
    def __init__(self,key_size=None,exponent=65537, src=None):
        if src is not None:
            self.private_key = self._import(src)
        else:
            self.private_key=rsa.generate_private_key(exponent,key_size)

    def transform(self,msg:bytes):
        return self.private_key.sign(
    msg,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
        ),
    hashes.SHA256()
    )

    def inverse_transform(self,msg:bytes):
        return self.private_key.decrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

    def sign(self,msg:bytes):
        return self.transform(msg)

    def decrypt(self,msg:bytes):
        return self.inverse_transform(msg)

    def public_key(self):
        return PublicKeyRSA(self.private_key.public_key())

    def _import (self, src:str):
        with open(src, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
        return private_key

    def _export(self, dest:str):
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(dest,"wb") as f:
            f.write(pem)

class PrivateKeyRSA1024(PrivateKeyRSA):
    def __init__(self,exponent=65537):
        super().__init__(1024,exponent)

class PrivateKeyRSA2048(PrivateKeyRSA):
    def __init__(self,exponent=65537):
        super().__init__(2048,exponent)

class PrivateKeyRSA4096(PrivateKeyRSA):
    def __init__(self,exponent=65537):
        super().__init__(4096,exponent)

class PrivateKeyRSA8192(PrivateKeyRSA):
    def __init__(self,exponent=65537):
        super().__init__(4096,exponent)

class PublicKeyRSA(Transformer):
    def __init__(self,public_key=None, src=None):
        if src != None:
            self.public_key = self._import(src)
        else :
            self.public_key = public_key
        pass

    def transform(self,msg:bytes):
        encoded=msg
        return self.public_key.encrypt(
            encoded,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def inverse_transform(self,msg:bytes,signature:bytes):

        try:
            self.public_key.verify(
                signature,
                msg,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def encrypt(self,msg:bytes):
        return self.transform(msg)

    def verify(self,msg:bytes,*args,**kwargs):
        return self.inverse_transform(msg,*args,**kwargs)

    def _import(self, src:str):
        with open(src, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        return public_key

    def _export(self, dest:str):
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1
        )

        with open(dest,"wb") as f:
            f.write(pem)


class DiffieHellmanExchange:
    def __init__(self, key_size, generator=2):
            self.parameters = dh.generate_parameters(generator=generator,key_size=key_size)
            self.private_key = self.parameters.generate_private_key()


    def public_key(self):
        return self.private_key.public_key()

    def shared_key(self,public_key):
        return self.private_key.exchange(public_key)


class DiffieHellmanExchange1024(DiffieHellmanExchange):
    def __init__(self,generator=2):
        super().__init__(key_size=1024,generator=generator)

class DiffieHellmanExchange2048(DiffieHellmanExchange):
    def __init__(self,generator=2):
        super().__init__(key_size=2048,generator=generator)

class DiffieHellmanExchangeFixed(DiffieHellmanExchange):
    def __init__(self,generator,group_cardinality):
        params_numbers = dh.DHParameterNumbers(generator,group_cardinality)
        self.parameters = params_numbers.parameters(default_backend())
        self.private_key=self.parameters.generate_private_key()


class ElGamalPrivateKey:
    def __init__(self,key_size=None,randfunc=get_random_bytes, src=None):
        if src is not None:
            self.priv, self.key_size= self._import(src)
        else:
            self.priv=ElGamal.generate(bits=key_size,randfunc=randfunc)
            self.key_size=key_size
    def public_key(self):
        return ElGamalPublicKey(self.priv.publickey(),key_size=self.key_size)

    def decrypt(self,E)->str:
        result=[]
        block_size=self.key_size//16
        for X in E:
            result.append(long_to_bytes(self.priv._decrypt(X)))
        return b''.join(result).decode("ascii")

    def _export(self,dest:str):
        with open(dest,"w") as f:
            f.write(f"p={self.priv.p}\n")
            f.write(f"g={self.priv.g}\n")
            f.write(f"y={self.priv.y}\n")
            f.write(f"x={self.priv.x}\n")
            f.write(f"ks={self.key_size}\n")
            
    def _import(self,src:str):
        with open(src, "r") as f:
            p = int(f.readline().rstrip().split('=')[1])
            g = int(f.readline().rstrip().split('=')[1])
            y = int(f.readline().rstrip().split('=')[1])
            x = int(f.readline().rstrip().split('=')[1])
            ks=int(f.readline().rstrip().split('=')[1])
            
            return (ElGamal.construct((p,g,y,x)),ks)
class ElGamalPublicKey:
    def __init__(self,publickey=None,key_size=None, src=None):
        if src is not None:
            self.pub,self.key_size = self._import(src)
        else:
            self.pub=publickey
            self.key_size=key_size
        self.b=int.from_bytes(os.urandom(self.key_size),byteorder="big")

    def encrypt(self, msg:str):
        encoded=msg.encode("ascii")
        X=[]
        result=[]
        block_size=self.key_size//16
        for i in range(len(encoded)//block_size):
            result.append(self.pub._encrypt(bytes_to_long(encoded[i*block_size:(i+1)*block_size]),K=self.b))
        if len(encoded)%block_size>0:
            result.append(self.pub._encrypt(bytes_to_long(encoded[(len(encoded)//block_size)*block_size:]),K=self.b))
        return result

    def _export(self,dest:str):
        with open(dest,"w") as f:
            f.write(f"p={self.pub.p}\n")
            f.write(f"g={self.pub.g}\n")
            f.write(f"y={self.pub.y}\n")
            f.write(f"ks={self.key_size}\n")
            
    def _import(self,src:str):
        with open(src, "r") as f:
            p = int(f.readline().rstrip().split('=')[1])
            g = int(f.readline().rstrip().split('=')[1])
            y = int(f.readline().rstrip().split('=')[1])
            ks=int(f.readline().rstrip().split('=')[1])
            return (ElGamal.construct((p,g,y)),ks)


if __name__=="__main__":
    #def _encrypt(self, M, K):
    # priv = ElGamal.generate(512,randfunc=get_random_bytes)
    # pub=priv.publickey()
    # u,v=pub._encrypt(546,K=4)
    # print(priv._decrypt((u,v)))
    privB=ElGamalPrivateKey(512)
    y = privB.priv.y # pub
    x = privB.priv.x # priv
    g = privB.priv.g # generator of the cyclic group
    p = privB.priv.p # order of the underlying prime field 
    #privC=ElGamal.construct((p,g,y,x))
    #print(privC._decrypt(privC.publickey()._encrypt(55,K=7)))
    pubB=privB.public_key()
    privC=ElGamalPrivateKey(512)
    pubC=privC.public_key()
    message="123456789"*500
    enc=pubB.encrypt(message)
    Y=privB.decrypt(enc)
    print(Y==message)

    #print(int.from_bytes(("123"*1000).encode("utf-8"),byteorder="little").to_bytes(20000,byteorder="little").decode("utf-8"))
    pass
    # private_key=PrivateKeyRSA1024()
    # public_key=private_key.public_key()
    # msg= b"encrypted data"
    # encoded=public_key.encrypt(msg)
    # print(f"{encoded.hex()}:{private_key.decrypt(encoded)}")

    # Sigature test
    # private_key = PrivateKeyRSA2048()
    # public_key = private_key.public_key()
    # msg = "This is going to be a signed message".encode("utf-8")
    # signature:bytes = private_key.sign(msg)
    # msg2 = "This is a bad message".encode("utf-8")
    # print(public_key.verify(msg2, signature))

    # Encryption/Decryption
    # privA = PrivateKeyRSA4096()
    # pubA = privA.public_key()
    # privB = PrivateKeyRSA4096()
    # pubB = privB.public_key()
    # msg:bytes = "Mon message secret".encode("utf-8")
    # encrypted = pubA.encrypt(msg)
    # decrypted = privB.decrypt(encrypted)
    # print(decrypted.decode("utf-8"))