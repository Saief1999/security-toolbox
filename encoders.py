from transformer import Transformer
import base64
class Encoder(Transformer):
    def encode(self,msg:str)->bytes:
        return self.transform(msg)
        
    def decode(self,msg:bytes)->str:
        return self.inverse_transform(msg)

class Base64Encoder(Encoder):
        
    def transform(self,msg:str)->bytes:
        return base64.b64encode(msg.encode("utf-8"))
        
    def inverse_transform(self,msg:bytes)->str:
        return base64.b64decode(msg).decode("utf-8")

class Base32Encoder(Encoder):
    def transform(self,msg:str)->bytes:
        return base64.b32encode(msg.encode("utf-8"))

    def inverse_transform(self,msg:bytes):
        return base64.b32decode(msg).decode("utf-8")

if __name__ == "__main__":
    encoder = Base32Encoder()
    encoded = encoder.encode("ABCDEFG")
    print(f"{encoded}:{encoder.decode(encoded)}")