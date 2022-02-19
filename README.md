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

- `Transformer` : An abstract class defining two main methods
  - `transform` : an operation on an input
  - `inverse_tranform` : the inverse of that operation

```mermaid
classDiagram

    class Transformer{
        +transform(**kwargs)*
        +inverse_transform(**kwargs)*
    }

    Transformer <|-- Encoder
    class Encoder {
        +encode(str msg) bytes
        +decode(bytes msg) str
    }

    Encoder <|-- Base32Encoder
    class Base32Encoder {
    }

    Encoder <|-- Base64Encoder
    class Base64Encoder {
    }

    Transformer <|-- Encryption
    class Encryption {
        +encrypt(str msg)* bytes
        +decrypt(str msg)* bytes
    }

    Encryption <|-- TripleDESEncryption
    class TripleDESEncryption {
    }

    Encryption <|-- AESEncryption
    class AESEncryption {
    }
    
    class Hashing {
    	+hash(str msg)* bytes
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

#### RSA

```mermaid
classDiagram

class Transformer {
    +transform()*
    +inverse_transform()*
}

Transformer <|-- PrivateKeyRSA
class PrivateKeyRSA {
	+sign(bytes msg) bytes
	+decrypt(bytes msg) bytes
	+_import(str src)
	+_export(str dest)
}

PrivateKeyRSA <|-- PrivateKeyRSA1024
class PrivateKeyRSA1024 {
	
}

PrivateKeyRSA <|-- PrivateKeyRSA2048
class PrivateKeyRSA2048 {
	
}

PrivateKeyRSA <|-- PrivateKeyRSA4096
class PrivateKeyRSA4096 {
	
}

PrivateKeyRSA <|-- PrivateKeyRSA8192
class PrivateKeyRSA8192 {
	
}
Transformer <|-- PublicKeyRSA
class PublicKeyRSA {
	+encrypt(bytes msg) bytes
	+verify (bytes msg, bytes signature) bool
	+_import(str dest)
	+_export(str dest)
}

```

#### Diffie Hellman

```mermaid
```



#### El Gamal

```mermaid
```



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
