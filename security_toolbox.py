from getpass import getpass
import sys
from asymmetric_encryption import PrivateKeyRSA, PublicKeyRSA
from authentication import Authentication
from cracking import DictionaryCracker
from encoders import Base64Encoder
from hashing import MD5Hash, SHA1Hash, SHA256Hash
from symmetric_encryption import AESEncryption, TripleDESEncryption
from user import User
from dotenv import dotenv_values

class SecurityToolbox:
    def __init__(self, email=None, password=None) -> None:
        self.authentication:Authentication = Authentication()
        self.config = dotenv_values(".env")
    
    def start(self):
        choice=0
        while choice not in {1, 2}:
            print("""
1. Enregistrement
2. Authentification       
""")
            choice = int(input("Choisissez votre choix: "))
            if choice == 1:
                self.authentication.register()
                next = self.start
            elif choice == 2:
                user:User= self.authentication.login()
                if user is None :
                    print("Identifiants invalides!")
                    choice=0
                    continue
                print(f"Bienvenu {user.firstname} {user.lastname}!")
                next = self.menu
            next()

    def encodingMenu(self):
        print("""
1. Codage
2. Décodage
""")
        choice=0
        while choice not in {1,2}:
            choice = int(input("Choisissez votre choix: "))
        msg:str
        encoder = Base64Encoder()
        if choice == 1:
           msg=input("Donnez le message à coder: ")
           print(f"Le message codé au format HEX: {encoder.encode(msg).hex()}")
        elif choice == 2:
            msg =input("Donnez le message à décoder au format HEX: ")
            print(f"Le message décodé est: {encoder.decode(bytearray.fromhex(msg))}")

    def hashingMenu(self):
        print("""
1. MD5
2. SHA1
3. SHA256
""")
        choice=0
        while choice not in {1,2,3}:
            choice = int(input("Choisissez votre choix: "))
        msg:str
        msg=input("Donnez le message à hacher: ")
        hash_choice = {1:MD5Hash(),2:SHA1Hash(),3:SHA256Hash()}
        print(f"le haché au format HEX est: {(hash_choice[choice])(msg).hex()}")


    def crackingMenu(self):
        print("""
1. MD5
2. SHA1
3. SHA256
""")
        choice=0
        while choice not in {1,2,3}:
            choice = int(input("Choisissez votre choix: "))
        msg:str
        msg=input("Donnez le Email haché: ")
        hash_choice = {1:MD5Hash(),2:SHA1Hash(),3:SHA256Hash()}
        cracker=DictionaryCracker(filename=self.config["crunched"])
        result = cracker.crack(bytearray.fromhex(msg),hash_function=hash_choice[choice])
        if result != False :
            print(f"Email: {result}")
        else :
            print("Email ne peut pas être cracké")

    def symmetricEncryptionMenu(self):
        print("""
1. DES3
2. AES
""")
        algorithm_choice=0
        while algorithm_choice not in {1,2}:
            algorithm_choice = int(input("Choisissez votre choix: "))
        encryption_choice=0
        print("""
1. Encryptage
2. Decryptage
""")
        while encryption_choice not in {1,2}:
            encryption_choice=int(input("Choisissez votre choix: "))
        msg:str=input("Donnez le message à {}: ".format("encrypter" if encryption_choice == 1 else "decrypter au format hex"))
        passphrase:str=getpass("Donnez le mot secret: ")
        iv=None
        if encryption_choice==2:
            iv=bytearray.fromhex(input("Donnez le vecteur d'initialisation au format HEX: "))
        if algorithm_choice == 1:
            encryptor=TripleDESEncryption(passphrase=passphrase,iv=iv)
            
        else:
            encryptor=AESEncryption(passphrase=passphrase,iv=iv)
        if encryption_choice==1:
            result,iv=encryptor.encrypt(msg)
            print(f"Le message encrypté au format hex est: {result.hex()}")
            print(f"Le vecteur d'initialisation au format hex est: {iv.hex()}")
        else:
            result = encryptor.decrypt(bytearray.fromhex(msg))    
            print(f"Le message decrypté est: {result}")

    def asymmetricEncryptionMenu(self):
        print("""
1. RSA
2. ElGamal
""")
        algorithm_choice=0
        while algorithm_choice not in {1,2}:
            algorithm_choice = int(input("Choisissez votre choix: "))
        encryption_choice=0
        print("""
1. Generation
2. Encryptage
3. Decryptage
4. Signature
5. Verification
""")
        while encryption_choice not in {1,2,3,4,5}:
            encryption_choice=int(input("Choisissez votre choix: "))
        if encryption_choice==1:
            key_size = input("Donner la taille de clé >= 1024")
            private_key:PrivateKeyRSA = PrivateKeyRSA(key_size)
            public_key:PublicKeyRSA = private_key.public_key()

            print(f"Private Key (Hex):{private_key.private_key.hex()}")
            print(f"Private Key (Hex):{public_key.private_key.hex()}")

        elif encryption_choice == 2:
            msg:str=input("Donnez le message à encrypter: ")
        elif encryption_choice == 3:
            pass
        elif encryption_choice == 4:
            pass
        elif encryption_choice == 5:
            pass
            
        msg:str=input("Donnez le message à {}: ".format("encrypter" if encryption_choice == 1 else "decrypter au format hex"))
        passphrase:str=getpass("Donnez le mot secret: ")
        iv=None
        if encryption_choice==2:
            iv=bytearray.fromhex(input("Donnez le vecteur d'initialisation au format HEX: "))
        if algorithm_choice == 1:
            encryptor=R
        else:
            pass # El Gamal 
        if encryption_choice==1:
            result,iv=encryptor.encrypt(msg)
            print(f"Le message encrypté au format hex est: {result.hex()}")
            print(f"Le vecteur d'initialisation au format hex est: {iv.hex()}")
        else:
            result = encryptor.decrypt(bytearray.fromhex(msg))    
            print(f"Le message decrypté est: {result}")


    def menu(self):
        while True:
            print("""Menu:
1. Codage et Décodage d'un message:
    1.1. Codage
    1.2. Décodage

2. Hashage d'un message:
    2.1. MD5
    2.2. SHA1
    2.3. SHA256
    
3. Craquage d'un message haché:
    3.1. MD5
    3.2. SHA1
    3.3. SHA256
    
4. Chiffrement et Déchiffrement symétrique d'un message:
    4.1. DES3
    4.2. AES256

5. Chiffrement et Déchiffrement asymétrique d'un message:
    5.1. RSA
    5.2. Elgamal
    
6. Communication sécurisée entre deux clients
7. Quitter
""")
            choice =0
            while choice not in range(1, 8):
                choice = int(input("Choisissez votre choix: "))
                if choice == 1:
                    self.encodingMenu()
                elif choice == 2:
                    self.hashingMenu()
                elif choice == 3:
                    self.crackingMenu()
                elif choice == 4:
                    self.symmetricEncryptionMenu()
                elif choice == 5:
                    self.asymmetricEncryptionMenu()
                elif choice == 6:
                    pass
                elif choice == 7:
                    sys.exit(0)        
                input("Press to continue...")

if __name__ == "__main__":
    args = sys.argv[1:] # gets args from the user
    #Todo: Incorporate phase 1 & phase 2
    toolbox = SecurityToolbox()
    toolbox.menu()
