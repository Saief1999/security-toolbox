import sys
from authentication import Authentication

class SecurityToolbox:
    def __init__(self, email=None, password=None) -> None:
        self.authentication:Authentication = Authentication()
        if ( email==None and password==None ):
            self.authentication.register()
    
        


if __name__ == "__main__":
    args = sys.argv[1:] # gets args from the user
    toolbox = SecurityToolbox()
