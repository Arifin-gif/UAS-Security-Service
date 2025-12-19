# client.py
from pydantic import BaseModel

class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class KeyStore(BaseModel):
    public_key_str: str

class RelayMessage(BaseModel):
    recipient: str
    encrypted_content: str

class VerifyRequest(BaseModel):
    username_pengirim: str
    message: str
    signature: str

class EncryptRequest(BaseModel):
    message: str
    key: str

class DecryptRequest(BaseModel):
    ciphertext: str
    key: str