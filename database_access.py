from pymongo import MongoClient
from dotenv import dotenv_values

from user import User


class SingletonMeta(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        """
        Possible changes to the value of the `__init__` argument do not affect
        the returned instance.
        """
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]

class DatabaseAccess(metaclass=SingletonMeta):
    def __init__(self) -> None:
        self.setup_db()


    def setup_db(self)->None:
        """Sets up the database
        """
        config = dotenv_values(".env")
        self.client:MongoClient = MongoClient(config["CONNECTION_STRING"])
        self.database = self.client["ssi"]
        self.users = self.database["users"]
    
    def create_user(self, user:User)->None:
        """Creates a New User

        Args:
            user (User): provided User
        """
        self.users.insert_one({
            "firstname": user.firstname,
            "lastname": user.lastname,
            "email": user.email,
            "password": user.password
        })

    def find_user(self, email:str, password:str)->None | User:
        """Finds a user and returns it

        Returns:
            User: found User, None if not found
        """
        result = self.users.find_one({ "email": email, "password": password })
        if result == None :
            return None
        return User(result["firstname"], result["lastname"], result["email"])

if __name__ == "__main__":
    dao = DatabaseAccess()
    # dao.create_user(User("Saief", "Zneti", "saief_zaneti@yahoo.com","45654"))
    user = dao.find_user("saief_zaneti@yahoo.com", "45654")
    print(user)
    