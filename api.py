# api.py
# Berisi logika utama API dan Endpoints
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt

# Import model dari client.py
from client import (
    UserRegister, UserLogin, KeyStore, 
    RelayMessage, VerifyRequest, EncryptRequest, DecryptRequest
)

# Import rumus dari crypto_utils.py (Pastikan file ini ada)
from crypto_utils import (
    generate_keys, sign_data, verify_signature,
    generate_symmetric_key, encrypt_message, decrypt_message
)

# Setup Router
router = APIRouter()

# Konfigurasi
SECRET_KEY = "rahasia_proyek_security_service"
ALGORITHM = "HS256"
security = HTTPBearer()

# Database Sementara (In-Memory)
users_db = {}
messages_db = []

# --- FUNGSI SECURITY (HELPER) ---
def create_jwt_token(username: str):
    payload = {"sub": username}
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username not in users_db:
             raise HTTPException(status_code=401, detail="User tidak dikenali")
        return username
    except Exception:
        raise HTTPException(status_code=401, detail="Token tidak valid")

# --- GROUP 1: AUTHENTICATION (Login/Register/Key) ---

@router.post("/register", tags=["Authentication"])
def register_user(user: UserRegister):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username sudah dipakai")
    users_db[user.username] = {"password": user.password, "public_key": None}
    return {"message": "Registrasi berhasil"}

@router.post("/login", tags=["Authentication"])
def login(user: UserLogin):
    if user.username not in users_db:
        raise HTTPException(status_code=400, detail="User tidak ditemukan")
    stored_data = users_db[user.username]
    if user.password != stored_data['password']:
        raise HTTPException(status_code=400, detail="Password salah")
    token = create_jwt_token(user.username)
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me", tags=["Authentication"])
def get_my_info(current_user: str = Depends(verify_token)):
    return {"username": current_user, "data": users_db[current_user]}

@router.post("/store", tags=["Authentication"])
def store_public_key(key_data: KeyStore, current_user: str = Depends(verify_token)):
    users_db[current_user]["public_key"] = key_data.public_key_str
    return {"message": "Public Key berhasil disimpan", "user": current_user}

# --- GROUP 2: CRYPTOGRAPHY (Encrypt/Verify) ---

@router.post("/verify", tags=["Cryptography"])
def verify_signature_endpoint(req: VerifyRequest):
    if req.username_pengirim not in users_db:
         raise HTTPException(404, "User pengirim tidak ditemukan")
    user_data = users_db[req.username_pengirim]
    if not user_data["public_key"]:
         raise HTTPException(400, "User belum memiliki Public Key")
         
    is_valid = verify_signature(user_data["public_key"], req.message.encode('utf-8'), req.signature)
    
    if is_valid:
        return {"status": "VALID", "detail": "Signature Valid (Asli)."}
    else:
        raise HTTPException(400, detail="INVALID! Signature Palsu.")

@router.post("/encrypt", tags=["Cryptography"])
def encrypt_tool(req: EncryptRequest):
    try:
        cipher = encrypt_message(req.key, req.message)
        return {"original": req.message, "encrypted": cipher}
    except:
        raise HTTPException(400, "Key Error")

@router.post("/decrypt", tags=["Cryptography"])
def decrypt_tool(req: DecryptRequest):
    try:
        original = decrypt_message(req.key, req.ciphertext)
        return {"decrypted": original}
    except:
        raise HTTPException(400, "Decrypt Error")

# --- GROUP 3: MESSAGING (Relay/Inbox) ---

@router.post("/relay", tags=["Messaging"])
def relay_message(msg: RelayMessage, sender: str = Depends(verify_token)):
    if msg.recipient not in users_db:
        raise HTTPException(404, "Penerima tidak ditemukan")
    
    new_msg = {
        "from": sender,
        "to": msg.recipient,
        "content": msg.encrypted_content
    }
    messages_db.append(new_msg)
    return {"status": "Terkirim", "detail": f"Pesan aman disimpan untuk {msg.recipient}"}

@router.get("/inbox", tags=["Messaging"])
def check_inbox(user: str = Depends(verify_token)):
    my_messages = [m for m in messages_db if m["to"] == user]
    return {"inbox": my_messages}

@router.post("/upload-pdf", tags=["File Signature"])
async def upload_pdf_sign(file: UploadFile = File(...), private_key: str = Form(...)):
    try:
        pdf_content = await file.read()
        signature = sign_data(private_key, pdf_content)
        return {
            "filename": file.filename,
            "status": "SIGNED",
            "digital_signature": signature
        }
    except Exception as e:
        raise HTTPException(400, detail=f"Gagal sign PDF: {str(e)}")

# --- GROUP 4: UTILITY ---

@router.get("/generate-keys", tags=["Utility"])
def get_keys():
    priv, pub = generate_keys()
    return {"private_key": priv, "public_key": pub}

@router.get("/generate-secret-key", tags=["Utility"])
def get_secret():
    from crypto_utils import generate_symmetric_key
    return {"secret_key": generate_symmetric_key()}