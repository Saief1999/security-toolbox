from transformer import Transformer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from encoders import Encoder

class PrivateKeyRSA(Transformer):
    def __init__(self,key_size,exponent=65537):
        self.private_key=rsa.generate_private_key(exponent,key_size)

    def transform(self,msg:str):
        return self.private_key.sign(
    msg,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
        ),
    hashes.SHA256()
    )

    def inverse_transform(self,msg:str):
        return self.private_key.decrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

    def sign(self,msg:str):
        return self.transform(msg)

    def decrypt(self,msg:str):
        return self.inverse_transform(msg)

    def public_key(self):
        return PublicKeyRSA(self.private_key.public_key())


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
    def __init__(self,public_key):
        self.public_key=public_key
        pass

    def transform(self,msg:str):
        encoded=msg
        return self.public_key.encrypt(
            encoded,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def inverse_transform(self,msg:str,signature:str):
        return self.public_key.verify(
            signature,
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def encrypt(self,msg:str):
        return self.transform(msg)

    def verify(self,msg:str,*args,**kwargs):
        return self.inverse_transform(msg,*args,**kwargs)


if __name__=="__main__":
    private_key=PrivateKeyRSA1024()
    public_key=private_key.public_key()
    msg= b"encrypted data"
    encoded=public_key.encrypt(msg)
    print(f"{encoded.hex()}:{private_key.decrypt(encoded)}")