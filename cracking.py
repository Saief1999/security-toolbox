import hashing
from abc import ABC,abstractmethod


class Cracker(ABC):
    @abstractmethod
    def crack(self,msg:str,*args,**kwargs):
        pass


class BruteForceCracker(Cracker):
    def __init__(self):
        self.alphabet = "abcdefghijklmnopqrstuvwxyz"
    def crack(self,hashed_password:str,hash_function,length=4):
        for L in range(length+1):
            S=list(self.alphabet[0]*L)
            E=list(self.alphabet[-1]*L)
            P=[0]*L
            while S!=E:
                passwd="".join(S)
                h1= hash_function(passwd)
                if h1 == hashed_password: # SHA256Hash().hash
                    return passwd
                for i in range(L):
                    if S[i] == self.alphabet[-1]:
                        S[i]=self.alphabet[0]
                        P[i]=0
                    else:
                        P[i]+=1
                        S[i]=self.alphabet[P[i]]
                        break 
            passwd="".join(E)
            h1=hash_function(passwd)
            if h1==hashed_password: # SHA256Hash().hash
                    return passwd
        return False

class DictionaryCracker(Cracker):
    def __init__(self):
        self.dictionary = []
    def crack(self,hashed_password:str,hash_function):
        for passwd in self.dictionary:
            h1 = hash_function(passwd)
            if (h1 == hashed_password) :
                return h1
        return False

if __name__=="__main__":
    cracker=BruteForceCracker()
    hasher=hashing.SHA256Hash()
    print(cracker.crack(hasher.hash("wxug"),hash_function=hasher.hash))
    #print("".join(['a','b','c']))

# @insat.ucar.tn: size 14
# xxxxxx.yyyyy@insat.ucar.tn   , x: a-z , y: a-z
# crunch 26 26 -t @@@@@@.@@@@@@insat.ucar.tn -l aaaaaaaaaaaa@aaaaaaaaaaaaa -o insat.dic