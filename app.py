import hashlib, base64, json, os
from datetime import datetime
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from cryptography.fernet import Fernet
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2
from qiskit import QuantumCircuit, transpile
from fastapi.responses import FileResponse


app = FastAPI()

# Tarayıcı erişimi için CORS ayarları
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

@app.get("/")

async def read_index():
    return FileResponse('index.html')


# --- VERİTABANI DOSYALARI ---
USERS_FILE = "users_db.json"
MESSAGES_FILE = "messages_db.json"

def load_data(file, default):
    if os.path.exists(file):
        with open(file, "r", encoding="utf-8") as f: return json.load(f)
    return default

def save_data(file, data):
    with open(file, "w", encoding="utf-8") as f: json.dump(data, f, indent=4)

db_users = load_data(USERS_FILE, {})
db_messages = load_data(MESSAGES_FILE, [])

# --- IBM TORINO BAĞLANTISI ---
# Kendi API Key'inizi buraya tırnak içine yapıştırın
IBM_API_KEY = os.environ.get("IBM_API_KEY")
service = None
backend = None

try:
    service = QiskitRuntimeService(channel="ibm_quantum_platform", token=IBM_API_KEY)
    # TALİMAT 1: Her zaman Torino'yu seçer
    backend = service.backend("ibm_torino")
    print(f"BAĞLANTI BAŞARILI: Kuantum İşlemci '{backend.name}' Kilitlendi.")
except Exception as e:
    print(f"UYARI: Donanım bağlantısı başarısız. Hata: {e}")

# --- VERİ MODELLERİ ---
class UserAuth(BaseModel):
    username: str
    password: str

class MsgSchema(BaseModel):
    sender: str
    receiver: str
    content: str
    is_file: bool = False
    file_name: str = ""

# --- KUANTUM RASTGELE SAYI ÜRETİMİ (TRANSPILE DESTEKLİ) ---
def get_q_bits(length=32):
    if backend is not None:
        try:
            print(f"--- [GERÇEK DONANIM İŞLEMİ BAŞLATILDI: {backend.name}] ---")
            qc = QuantumCircuit(1, 1)
            qc.h(0)
            qc.measure(0, 0)
            
            # TALİMAT 2: Donanım hatasını önlemek için devreyi Torino diline çevirir
            transpiled_circuit = transpile(qc, backend=backend)
            
            sampler = SamplerV2(backend)
            job = sampler.run([transpiled_circuit], shots=length)
            
            # KANIT: Dashboard'da sorgulayabileceğiniz Job ID
            print(f"JOB ID: {job.job_id()}")
            
            result = job.result()[0]
            bits = "".join(result.data.c.get_bitstrings())
            
            print(f"IBM TORINO'DAN GELEN VERİ: {bits}")
            return bits
        except Exception as e:
            print(f"KUANTUM DONANIM HATASI: {e}. Simülatöre geçiliyor...")
    
    # Donanım meşgulse veya hata verirse yerel güvenli rastgelelik kullanılır
    return bin(int.from_bytes(os.urandom(length // 8), 'big'))[2:].zfill(length)

# --- ENDPOINTLER ---

@app.post("/register")
async def register(user: UserAuth):
    if user.username in db_users: 
        raise HTTPException(status_code=400, detail="Kullanıcı zaten var.")
    q_salt = get_q_bits(64)
    hashed_pass = hashlib.sha3_512((user.password + q_salt).encode()).hexdigest()
    db_users[user.username] = {"password": hashed_pass, "salt": q_salt}
    save_data(USERS_FILE, db_users)
    return {"status": "ok"}

@app.post("/login")
async def login(user: UserAuth):
    if user.username in db_users:
        u_data = db_users[user.username]
        check = hashlib.sha3_512((user.password + u_data["salt"]).encode()).hexdigest()
        if check == u_data["password"]:
            return {"status": "ok"}
    raise HTTPException(status_code=401, detail="Hatalı kullanıcı veya şifre.")

@app.post("/send_message")
async def send(msg: MsgSchema):
    # Kuantum bitlerini al ve şifreleme anahtarı oluştur
    q_bits = get_q_bits(256)
    key = base64.urlsafe_b64encode(int(q_bits, 2).to_bytes(32, 'big'))
    cipher = Fernet(key)
    
    # İçeriği (metin veya dosya) şifrele
    enc_content = cipher.encrypt(msg.content.encode()).decode()
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    db_messages.append({
        "sender": msg.sender,
        "receiver": msg.receiver,
        "content": enc_content,
        "key": key.decode(),
        "time": timestamp,
        "is_file": msg.is_file,
        "file_name": msg.file_name
    })
    save_data(MESSAGES_FILE, db_messages)
    return {"status": "sent"}

@app.get("/get_all_messages")
async def get_all():
    decrypted_list = []
    for m in db_messages:
        try:
            cipher = Fernet(m["key"].encode())
            decrypted_content = cipher.decrypt(m["content"].encode()).decode()
            decrypted_list.append({
                "sender": m["sender"],
                "receiver": m["receiver"],
                "message": decrypted_content,
                "time": m.get("time", ""),
                "is_file": m.get("is_file", False),
                "file_name": m.get("file_name", "")
            })
        except:
            continue
    return decrypted_list

# --- SUNUCUYU AYAKTA TUTAN BÖLÜM ---
if __name__ == "__main__":
    import uvicorn
    import os
    # Render portu otomatik atar, yoksa 8000 kullanır
    port = int(os.environ.get("PORT", 8000))

    uvicorn.run(app, host="0.0.0.0", port=port)



