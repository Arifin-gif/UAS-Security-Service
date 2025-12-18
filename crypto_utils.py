# crypto_utils.py
# File ini berisi rumus matematika untuk Enkripsi & Tanda Tangan
# JANGAN DIUBAH!

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.fernet import Fernet
import base64

# --- BAGIAN 1: Asymmetric (RSA/ECC) ---
# Untuk Tanda Tangan Digital (Signature)

def generate_keys():
    """Membuat pasangan kunci Private & Public."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem.decode('utf-8'), pub_pem.decode('utf-8')

def sign_data(private_key_str: str, data: bytes) -> str:
    """
    Menandatangani data (bisa teks atau file PDF).
    Input 'data' harus dalam bentuk bytes.
    """
    try:
        # Jika input cuma string biasa, ubah jadi bytes
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        private_key = serialization.load_pem_private_key(
            private_key_str.encode('utf-8'), password=None
        )
        signature = private_key.sign(
            data, ec.ECDSA(hashes.SHA256())
        )
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Gagal sign data: {e}")

def verify_signature(public_key_str: str, data: bytes, signature_str: str) -> bool:
    """
    Mengecek keaslian tanda tangan.
    Input 'data' harus dalam bentuk bytes.
    """
    try:
        # Jika input data berupa string, ubah jadi bytes dulu
        if isinstance(data, str):
            data = data.encode('utf-8')

        public_key = serialization.load_pem_public_key(public_key_str.encode('utf-8'))
        signature_bytes = base64.b64decode(signature_str)
        
        public_key.verify(signature_bytes, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

# --- BAGIAN 2: Symmetric (AES) ---
# Untuk Enkripsi Pesan Rahasia

def generate_symmetric_key() -> str:
    """Membuat kunci rahasia untuk AES."""
    return Fernet.generate_key().decode('utf-8')

def encrypt_message(key: str, message: str) -> str:
    """Mengacak pesan teks."""
    f = Fernet(key.encode('utf-8'))
    return f.encrypt(message.encode('utf-8')).decode('utf-8')

def decrypt_message(key: str, ciphertext: str) -> str:
    """Membaca pesan acak."""
    f = Fernet(key.encode('utf-8'))
    return f.decrypt(ciphertext.encode('utf-8')).decode('utf-8')