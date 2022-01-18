from transformer import Transformer

class Encryption(Transformer):
    def encrypt(self,msg:str,*args,**kwargs)->bytes:
        return self.transform(msg,*args,**kwargs)
    
    def decrypt(self,msg:str,*args,**kwargs)->bytes:
        return self.inverse_transform(msg,*args,**kwargs)