# Security Toolbox

## Overview

- This is a small tool providing some basic security operations (hashing, encryption, ...)

## Modelisation 

### General Flow

```mermaid
stateDiagram-v2
    [*] --> Register
    [*] --> Authenticate 
    [*] --> Chat
    Chat --> send
    Chat --> receive
    Authenticate --> 2_factor_auth: email&pass
    2_factor_auth --> Menu: code
    Menu --> Hashing
    Menu --> Cracking_hashed
    Menu --> Encoding
    Menu --> Symmetric_Encryption
    Menu --> Asymmetric_Encryption

```



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
- `key_strech` : In order to be able to use a passphrase as our key for cryptographic operations, we're using a technique called **key stretching**. We're using the **Concat KDF algorithm**
  - **ConcatKDF** (Concatenation Key Derivation Function) is defined by the NIST  to be used to derive keys for use after a Key Exchange negotiation operation.
  - *Explication*: KDF hashes the concatenation of a 4-byte counter initialized at 1  (big-endian), the shared secret obtained by ECDH, and some other  information passed as input. The counter is incremented and the process  is repeated until enough data was produced. The concatenation of the  hashes, truncated as needed, forms the output to be used as key

- `pad / unpad`: When using AES or TripleDES for encryption , **the message needs to be multiple of Block Size**, we're using a know algorithm called **`PKCS7`** to perform the padding and unpadding to the appropriate size.

```mermaid
classDiagram

    class Transformer{
    	<<abstract>>
        +transform(**kwargs)*
        +inverse_transform(**kwargs)*
    }

    Transformer <|-- Encoder
    class Encoder {
    	<<abstract>>
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
    	<<abstract>>
        +encrypt(str msg)* bytes
        +decrypt(str msg)* bytes
    }

    Encryption <|-- TripleDESEncryption
    class TripleDESEncryption {
    	+key_stretch()
    	+pad()
    	+unpad()
    }

    Encryption <|-- AESEncryption
    class AESEncryption {
    	+key_stretch()
    	+pad()
    	+unpad()
    }
    
    class Hashing {
    	<<abstract>>
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

This implementation is straight forward, we have two classes :

- `PrivateKeyRSA` : where we can `sign`and `decrypt` a message
- `PublicKeyRSA` : where we can `encrypt` and `verify` a message

```mermaid
classDiagram

class Transformer {
	<<abstract>>
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
classDiagram

class DiffieHellmanExchange {
	+public_key()
	+shared_key()
}

DiffieHellmanExchange <|-- DiffieHellmanExchange1024
class DiffieHellmanExchange1024 {
	
}

DiffieHellmanExchange <|-- DiffieHellmanExchange2048
class DiffieHellmanExchange2048 {
	
}

DiffieHellmanExchange <|-- DiffieHellmanExchangeFixed
class DiffieHellmanExchangeFixed {
	
}
```

#### El Gamal

- Knowing that **The message should not be longer than the key**, when we encrypt we **divide** our message to multiple **blocks** shorter in length than the key. Then we encrypt each one individually, we then return the result as a list, the inverse operation is done when decrypting.

```mermaid
classDiagram

class ElGamalPrivateKey {
	+public_key()
	+decrypt(list~pair~) str
	_import(str src)
	_expor(str dest)
}

class ElGamalPublicKey {
	+encrypt(str msg) list~pair~
	+_export(str dest)
	+_import(str src)
}

```

### Kerberos General Flow

```mermaid

sequenceDiagram
	saiefzneti.tn->>Kerberos Authentication Server (KAS): kinit
	Kerberos Authentication Server (KAS)->> saiefzneti.tn: Ticket grating ticket
    ramizouari.tn->>Kerberos Authentication Server (KAS): kinit
    Kerberos Authentication Server (KAS)->> ramizouari.tn: Ticket grating ticket

```

 ```mermaid
 sequenceDiagram
   	par Prepare Client
   		saiefzneti.tn->>saiefzneti.tn: authGSSClientInit(saiefzneti.tn, securitytools@ramizouari.tn)
 		saiefzneti.tn->>Ticket Granting Server(TGS): Ask for ticket for ramizouari.tn
 		Ticket Granting Server(TGS)->> saiefzneti.tn: Ticket for to access ramizouari.tn
     end
     par Prepare Server
 		ramizouari.tn->>ramizouari.tn: authGSSClientInit(securitytools@ramizouari.tn)
 	end
 	alt Authentication
 		saiefzneti.tn->>saiefzneti.tn: authGSSClientStep(context) [ prepare ticket to send it]
 		saiefzneti.tn->>ramizouari.tn: send ticket
 		ramizouari.tn->>ramizouari.tn: authGSSServerStep(context, ticket)[ process ticket]
 		ramizouari.tn->>saiefzneti.tn: feedback
 	end
 ```



```mermaid
sequenceDiagram
loop Chat
	saiefzneti.tn->>saiefzneti.tn: encode(message)
	saiefzneti.tn->>saiefzneti.tn: authGSSClientWrap(context, encoded_message)
	saiefzneti.tn->>ramizouari.tn: send_message
	ramizouari.tn->>ramizouari.tn: receive_message
    ramizouari.tn->>ramizouari.tn: authGSSClientUnwrap(context, encoded_encrypted_message)
    ramizouari.tn->>ramizouari.tn: decode(encoded_message)
end
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
