# main.py
# Entry point server
from fastapi import FastAPI
from api import router  # Panggil router dari file api.py

# Inisialisasi Aplikasi
app = FastAPI(
    title="Security Service API",
    description="Secure API with Encryption, Digital Signature, and JWT Auth",
    version="1.0.0"
)

# Hubungkan Endpoint
app.include_router(router)

@app.get("/")
def read_root():
    return {"message": "System is Running..."}

if __name__ == "__main__":
    import uvicorn
    # Menjalankan server
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)