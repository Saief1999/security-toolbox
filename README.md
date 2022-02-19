# security-toolbox

## Overview

- This is a small tool providing some basic security operations

## Description 

### Authentication & Signup 

```mermaid
classDiagram

    Authentication --  DatabaseAccess : authenticate
   	DatabaseAccess -- User : find_user / create_user
    
    class Authentication {
        +register()
        +login()
        +generate_code()
        +send_verification_code()
    }
    
    class User {
    	+firstname
    	+lastname
    	+email
    	+password
    }
    
    class DatabaseAccess {
    	+setup_db()
    	+create_user()
    	+find_user()
    }
    
```

### Hashing, Encoding & Symmetric encryption

```mermaid
classDiagram

    class Transformer{
        +transform()*
        +inverse_transform()*
    }

    Transformer <|-- Encoder
    class Encoder {
        +encode()
        +decode()
    }

    Encoder <|-- Base32Encoder
    class Base32Encoder {
    }

    Encoder <|-- Base64Encoder
    class Base64Encoder {
    }

    Transformer <|-- Encryption
    class Encryption {
        +encrypt()
        +decrypt()
    }

    Encryption <|-- TripleDESEncryption
    class TripleDESEncryption {
    }

    Encryption <|-- AESEncryption
    class AESEncryption {
    }
    
    class Hashing {
    	+hash()*
    }
    
    Hashing <|-- SHA512Hash
    class SHA512Hash {
    }
    
    Hashing <|-- SHA1Hash
    class SHA1Hash {
    
    }
    
    Hashing <|-- MD5Hash
    class MD5Hash {
    
    }
    
    
```

### Asymmetric encryption

## Features

### Authentication & Signup

- User must sign up in order to use the tool (saved in a mongodb)
- supports 2 factor authentication

### Menu

1. Encoding / Decoding ()
2. Hashing
3. Brute forcing a hashed email
4. Symmetric Encryption / Decryption (AES, Triple DES)
5. Asymmetric Encryption / Decryption (RSA,ElGamal)
