from getpass import getpass
import sys
from asymmetric_encryption import ElGamalPrivateKey, ElGamalPublicKey, PrivateKeyRSA, PublicKeyRSA
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
                print("Passez à l'authentification svp")
                next = self.start
            elif choice == 2:
                user:User= self.authentication.login()
                if user is None :
                    print("Identifiants invalides!")
                    choice=0
                    continue
                else:
                    code = self.authentication.genereate_code()
                    self.authentication.send_verification_code(user, code)
                    while (True):
                        input_code = input("Donner votre code: ")
                        if (input_code == code):
                            break
                        else:
                            print("Code Invalide!") 
                print(f"Bienvenue {user.firstname} {user.lastname}!")
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
           print(f"Le message codé à base 64: {encoder.encode(msg).decode('utf-8')}")
        elif choice == 2:
            msg =input("Donnez le message à décoder: ")
            print(f"Le message décodé de la base 64 est: {encoder.decode(msg.encode('utf-8'))}")

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
            encryptor=TripleDESEncryption(passphrase=passphrase)
            
        else:
            encryptor=AESEncryption(passphrase=passphrase)
        if encryption_choice==1:
            result,iv=encryptor.encrypt(msg)
            print(f"Le message encrypté au format hex est: {result.hex()}")
            print(f"Le vecteur d'initialisation au format hex est: {iv.hex()}")
        else:
            result = encryptor.decrypt(bytearray.fromhex(msg),iv)    
            print(f"Le message decrypté est: {result}")

    def asymmetricEncryptionMenu(self):
        print("""
1. RSA
2. ElGamal
""")
        algorithm_choice=0
        while algorithm_choice not in {1,2}:
            algorithm_choice = int(input("Choisissez votre choix: "))
        if algorithm_choice == 1:
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
                key_size = int(input("Donnez la taille de clé >= 1024: "))
                private_key:PrivateKeyRSA = PrivateKeyRSA(key_size)
                public_key:PublicKeyRSA = private_key.public_key()
                dest_priv=input("Donner le nom de fichier de la clé privé [privRSA.pem]: ") or "privRSA.pem"
                private_key._export(dest_priv)
                print(f"Clé privé RSA exporté vers {dest_priv}")
                dest_pub=input("Donner le nom de fichier de la clé publique [pubRSA.pem]: ") or "pubRSA.pem"
                public_key._export(dest_pub)
                print(f"Clé publique RSA exporté vers {dest_pub}")
            elif encryption_choice == 2:
                msg:str=input("Donnez le message à encrypter: ")
                src:str=input("Donnez le fichier contenant la clé publique [pubRSA.pem]: ") or "pubRSA.pem"
                public_key = PublicKeyRSA(src=src)
                print(f"Le message encrypté au format hex est: {public_key.encrypt(msg.encode('utf-8')).hex()}")
            elif encryption_choice == 3:
                msg=bytes(bytearray.fromhex(input("Donnez le message à décrypter au format HEX: ")))
                src:str=input("Donnez le fichier contenant la clé privé [privRSA.pem]: ") or "privRSA.pem"
                private_key = PrivateKeyRSA(src=src)
                print(f"Le message décrypté est: {private_key.decrypt(msg).decode('utf-8')}")
            elif encryption_choice == 4:
                msg:str=input("Donnez le message à signer: ")
                src:str=input("Donnez le fichier contenant la clé privé [privRSA.pem]: ") or "privRSA.pem"
                private_key = PrivateKeyRSA(src=src)
                print(f"La signature au format hex est: {private_key.sign(msg.encode('utf-8')).hex()}")
            elif encryption_choice == 5:
                signature:bytes=bytes(bytearray.fromhex(input("Donner la signature: ")))
                msg:str= input("Donnez le message à vérifier: ")
                src:str=input("Donnez le fichier contenant la clé publique [pubRSA.pem]: ") or "pubRSA.pem"
                public_key = PublicKeyRSA(src=src)
                verification = public_key.verify(msg.encode("utf-8"), signature)
                if (verification):
                    print("Bonne Signature")
                else:
                    print("Mauvaise Signature")
        else: # El Gamal
            encryption_choice = 0
            print("""
1. Generation
2. Encryptage
3. Decryptage
""")
            while encryption_choice not in {1,2,3}:
                encryption_choice=int(input("Choisissez votre choix: "))
            if encryption_choice==1:

                key_size = int(input("Donnez la taille de clé >= 1024: "))
                private_key:ElGamalPrivateKey = ElGamalPrivateKey(key_size=key_size)
                dest_priv=input("Donner le nom de fichier de la clé privé [privElGam.gam]: ") or "privElGam.gam"
                private_key._export(dest=dest_priv)
                print(f"Clé privé ElGamal exporté vers {dest_priv}")

                public_key:ElGamalPublicKey = private_key.public_key()
                dest_pub=input("Donner le nom de fichier de la clé publique [pubElGam.gam]: ") or "pubElGam.gam"
                public_key._export(dest=dest_pub)
                print(f"Clé publique ElGamal exporté vers {dest_pub}")

            elif encryption_choice == 2:
                msg:str=input("Donnez le message à encrypter: ")
                src:str=input("Donnez le fichier contenant la clé publique [pubElGam.gam]: ") or "pubElGam.gam"
                public_key = ElGamalPublicKey(src=src)
                print(f"Le message encrypté au format est: {public_key.encrypt(msg)}")
            elif encryption_choice == 3:
                l = []
                size = int(input("Donner le nombre de blocks[1]: ")) or 1
                for _ in range (1, size+1):
                    u = int(input("U: "))
                    v = int(input("V: "))
                    l.append([u,v])
                src:str=input("Donnez le fichier contenant la clé privé [privElGam.gam]: ") or "privElGam.gam"
                private_key = ElGamalPrivateKey(src=src)
                print(f"Le message décrypté est: {private_key.decrypt(l)}") 

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
    
7. Quitter
""")
# 6. Communication sécurisée entre deux clients
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
                input("Appuyez quelque chose pour continuer...")

if __name__ == "__main__":
    args = sys.argv[1:] # gets args from the user
    #Todo: Incorporate phase 1 & phase 2
    toolbox = SecurityToolbox()
    # toolbox.menu()
    toolbox.start()