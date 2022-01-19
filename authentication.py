from __future__ import annotations

from pyclbr import Function
import re
from getpass import getpass
from database_access import DatabaseAccess
from hashing import SHA256Hash
from user import User


# TODO : Hashing the passwords
class Authentication:
    """Responsible For login/register
    """

    def __init__(self) -> None:
        self.dao = DatabaseAccess()

    def register(self):
        firstname:str=self.get_field("First Name", self.is_field_not_empty, "First Name should not be empty!") 
        lastname:str=self.get_field("Last Name", self.is_field_not_empty, "Last Name should not be empty!") 
        email:str=self.get_field("Email",self.is_email_valid, "Email is Invalid!")
        password:str=self.get_pass()
        password:str = str(SHA256Hash().hash(password).hex())
        # print(f"{firstname}:{lastname}:{email}:{password}")
        self.dao.create_user(User(firstname, lastname, email, password))


    def get_field(self, fieldname:str, validator:Function=lambda v :True, error:str=None)->any:
        """Gets sanitized field after validation

        Args:
            fieldname (str): The name of the field
            validator (Function, optional): the field validator. Defaults to a function that always returns true.
            error (str, optional): Error message in case of a validator error. Defaults to None.

        Returns:
            any: Sanitzed Field
        """
        while(True):
            field = input(f"{fieldname}: ")
            if validator(field): 
                return field
            if(error is not None):
                print(error)


    def get_pass(self)->str:
        """Gets user registration password

        Returns:
            str: sanitized password
        """
        confirmed = False
        while (not confirmed):
            password = getpass("Password: ")
            if (len(password) == 0):
                print("Password should not be empty!")
                continue
            confirm_password = getpass("Confirm Password: ")
            if (password != confirm_password):
                print("Passwords don't match!")
            else:
                confirmed=True
        return password

    def is_password_valid(self, password:str)->bool:
        """Checks whether a password is valid

        Args:
            password (str): provided password

        Returns:
            bool: True if password is valid
        """
        return self.is_field_not_empty(password)

    def is_email_valid(self, email:str)->bool:
        """Checks whether an email is valid

        Args:
            email (str): provided email

        Returns:
            bool: True if email is valid
        """
        match = re.match("[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
            email
        )
        return bool(match)

    def is_field_not_empty(self, field:str)->bool:
        """Checks whether a field is not empty

        Args:
            field (str): Field to check

        Returns:
            bool: True if field is not empty
        """
        return len(field) != 0

    def login(self)->User|None:
        email:str = input("Email: ")
        password:str = getpass("Password: ")
        password:str = str(SHA256Hash().hash(password).hex())
        user:User = self.dao.find_user(email, password)
        if (user is None):
            return None
        return user


if __name__ == "__main__":
    authentication:Authentication = Authentication()
    authentication.register()