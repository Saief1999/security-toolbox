import sys
from authentication import Authentication

class SecurityToolbox:
    def __init__(self, email=None, password=None) -> None:
        self.authentication:Authentication = Authentication()
        if ( email==None and password==None ):
            self.authentication.register()
    
        


if __name__ == "__main__":
    args = sys.argv[1:] # gets args from the user
    #Todo: Incorporate phase 1 & phase 2
    #toolbox = SecurityToolbox()
    print("""Menu:
    1. Codage et Décodage d'un message:
        a. Codage
        b. Décodage
    
    2. Hashage d'un message:
        a. MD5
        b. SHA1
        c. SHA256
        
    3. Craquage d'un message haché:
        a. MD5
        b. SHA1
        c. SHA256
        
    4. Chiffrement et Déchiffrement symétrique d'un message:
        a. DES
        b. AES256
    
    5. Chiffrement et Déchiffrement asymétrique d'un message:
        a. RSA
        b. Elgamal
        
    6. Communication sécurisée entre deux clients
    7. Quitter
    """)
    choice=0
    while choice not in range(1, 8):
        choice = int(input("Choisissez votre choix: "))
