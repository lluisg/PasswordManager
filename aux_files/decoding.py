import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from security import hash_password


def decode(message):
    password_provided = "password" # This is input in the form of a string
    password = password_provided.encode() # Convert to type bytes
    pass2 = password_provided+'1296'
    # salt = str(hash(pass2)).decode("utf-8")
    salt = str(hash(pass2)).encode()
    print('salt2', salt)
    print('\n')
    # salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once

    f = Fernet(key)
    decrypted = f.decrypt(message)
    return decrypted
