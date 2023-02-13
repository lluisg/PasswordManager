from passlib.context import CryptContext
from passlib.hash import pbkdf2_sha256
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

user_file = 'user.info'


def hash_password2(password):
    # custom_pbkdf2 = pbkdf2_sha256.using(salt='123456'.encode())
    return pbkdf2_sha256.hash(password)


def resource_path(relative_path):
        if hasattr(sys, '_MEIPASS'):
            return os.path.join(sys._MEIPASS, relative_path)
        return os.path.join(os.path.abspath("."), relative_path)

pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=30000
)

def hash_password(password):
    return pwd_context.encrypt(password)

def read_password():
    f = open(resource_path(user_file), 'r')
    passw = f.readline()
    if passw[-1] == '\n':
        passw = passw[:-1]
    f.close()
    return passw

def check_hash_password(password):
    hashed = read_password()
    return pwd_context.verify(password, hashed)

def encrypt_password(message, password):
    key = get_key(password)
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    return encrypted.decode()

def deencrypt_password(message, password):
    key = get_key(password)
    f = Fernet(key)
    decrypted = f.decrypt(message.encode())
    return decrypted.decode()

def get_key(password_provided):
    password = password_provided.encode() # Convert to type bytes
    salt = str(password_provided+'1296@@3dasf!##sdf').encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once
    return key
