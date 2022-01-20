class User:
    """The User class
    """
    def __init__(self, firstname:str=None, lastname:str=None, email:str=None, password:str=None, verified:bool=False, code:bool=None) -> None:
        self.firstname = firstname
        self.lastname = lastname
        self.email = email 
        self.password = password
        self.verified = verified
        self.code = code

    def __repr__(self) -> str:
        return f"{self.formatted(self.firstname)} {self.formatted(self.lastname)}:{self.formatted(self.email)}:{self.formatted(self.password)}"
        
    def formatted(self, val):
        if (val is None) :
            return ""
        return val
