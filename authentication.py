from __future__ import annotations
import math,random
from multiprocessing import context
import smtplib, ssl


from pyclbr import Function
import re
from getpass import getpass
from database_access import DatabaseAccess
from hashing import SHA256Hash
from user import User
from dotenv import dotenv_values


class Authentication:
    """Responsible For login/register
    """

    def __init__(self) -> None:
        self.dao = DatabaseAccess()
        self.config = dotenv_values(".env")

    def register(self):
        firstname:str=self.get_field("Prénom", self.is_field_not_empty, "Prénom ne doit pas être vide!") 
        lastname:str=self.get_field("Nom", self.is_field_not_empty, "Nom ne doit pas être vide!") 
        email:str=self.get_field("Email",self.is_email_valid, "Email est Invalide!")
        password:str=self.get_pass()
        password:str = str(SHA256Hash().hash(password).hex())
        # print(f"{firstname}:{lastname}:{email}:{password}")
        user = User(firstname, lastname, email, password)
        self.dao.create_user(user)


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
            password = getpass("Mot de passe: ")
            if (len(password) == 0):
                print("Mot de passe ne doit pas être vide!")
                continue
            confirm_password = getpass("Confirmez Mot de passe: ")
            if (password != confirm_password):
                print("Mots de passe ne sont pas les mêmes!")
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

    def genereate_code(self):
        digits = "0123456789"
        code=""
        for i in range(8):
            code += digits[math.floor(random.random()*10)]
        return code
    
    def send_verification_code(self, user:User, code:str):
        context = ssl.create_default_context()
        message=f"""
Subject: Verification de compte

Hello {user.firstname} {user.lastname}!
Voici votre code de verification {code}
"""
        with smtplib.SMTP(self.config["smtp_server"],int(self.config["smtp_port"])) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(self.config["mailer_email"], self.config["mailer_password"])
            server.sendmail(self.config["mailer_email"], user.email, message)
            print(f"Code envoyé vers {user.email}")


if __name__ == "__main__":
    authentication:Authentication = Authentication()
    authentication.register()

  