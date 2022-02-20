from cryptography.hazmat.primitives import hashes
from abc import ABC

class Hashing(ABC):
    def __init__(self,hash_function):
        self.hash_function=hash_function
        pass
    def __call__(self,msg:str)->bytes:
        return self.hash(msg)
    def hash(self,msg:str)->bytes:
        digest = hashes.Hash(self.hash_function)
        digest.update(msg.encode("utf-8"))
        return digest.finalize()
    

class SHA512Hash(Hashing):
    def __init__(self):
        super().__init__(hashes.SHA256())

class SHA256Hash(Hashing):
    def __init__(self):
        super().__init__(hashes.SHA256())

class SHA1Hash(Hashing):
    def __init__(self):
        super().__init__(hashes.SHA1())


class MD5Hash(Hashing):
    def __init__(self):
        super().__init__(hashes.MD5())

if __name__ == "__main__":
    for hash in [SHA1Hash(),SHA256Hash(),MD5Hash()]:
        print(hash("Hello World").hex())

"""
Expected Output:
SHA1: 0a4d55a8d778e5022fab701977c5d840bbc486d0
SHA256: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
MD5: b10a8db164e0754105b7a99be72e3fe5
"""