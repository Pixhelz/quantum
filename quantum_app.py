import streamlit as st
import os
from qiskit import QuantumCircuit, transpile
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler
from qiskit.visualization import circuit_drawer

# 1. Sayfa Ayarları
st.set_page_config(page_title="Quantum Vault", page_icon="🔐", layout="wide")

# --- 🌍 DİL SİSTEMİ (SESSION STATE) ---
if 'lang' not in st.session_state:
    st.session_state.lang = "Turkish"

st.sidebar.title("Settings / Ayarlar")
lang_choice = st.sidebar.selectbox(
    "Dil Seçin / Select Language", 
    ["Turkish", "English"], 
    index=0 if st.session_state.lang == "Turkish" else 1
)
st.session_state.lang = lang_choice

# Dil Paketleri
texts = {
    "Turkish": {
        "title": "🔐 Quantum Vault: Kuantum Arama Portalı",
        "header": "Grover Algoritması ile Kuantum Arama",
        "desc": "IBM Torino (İtalya) donanımı üzerinde 3-qubitlik bir arama gerçekleştirin.",
        "select": "Aranacak hedef sayıyı seçin (0-7):",
        "btn": "Kuantum Aramayı Başlat 🚀",
        "working": "İtalya'ya bağlanılıyor, devre hazırlanıyor...",
        "results": "Kuantum Ölçüm Sonuçları",
        "circuit_title": "Oluşturulan Kuantum Devresi",
        "error_token": "Hata: IBM_QUANTUM_TOKEN bulunamadı!",
        "footer": "12. Sınıf Portfolyo Projesi - Pixhelz"
    },
    "English": {
        "title": "🔐 Quantum Vault: Quantum Search Portal",
        "header": "Quantum Search via Grover's Algorithm",
        "desc": "Perform a 3-qubit search on IBM Torino (Italy) hardware.",
        "select": "Select target number to search (0-7):",
        "btn": "Start Quantum Search 🚀",
        "working": "Connecting to Italy, preparing circuit...",
        "results": "Quantum Measurement Results",
        "circuit_title": "Generated Quantum Circuit",
        "error_token": "Error: IBM_QUANTUM_TOKEN not found!",
        "footer": "12th Grade Portfolio Project - Pixhelz"
    }
}

L = texts[st.session_state.lang]

# --- 🛠️ KUANTUM FONKSİYONLARI ---

def create_grover_circuit(target):
    """3 qubitlik Grover Algoritması devresi oluşturur"""
    qc = QuantumCircuit(3)
    
    # 1. Süperpozisyon (Hadamard)
    qc.h(range(3))
    
    # 2. Oracle (Hedefi İşaretleme)
    target_bin = format(target, '03b')[::-1]
    for i, bit in enumerate(target_bin):
        if bit == '0':
            qc.x(i)
    qc.h(2)
    qc.ccx(0, 1, 2)
    qc.h(2)
    for i, bit in enumerate(target_bin):
        if bit == '0':
            qc.x(i)
            
    # 3. Diffuser (Genlik Artırma)
    qc.h(range(3))
    qc.x(range(3))
    qc.h(2)
    qc.ccx(0, 1, 2)
    qc.h(2)
    qc.x(range(3))
    qc.h(range(3))
    
    qc.measure_all()
    return qc

# --- 🖥️ ARAYÜZ ---
st.title(L["title"])
st.info(L["desc"])

target_number = st.slider(L["select"], 0, 7, 3)

if st.button(L["btn"], use_container_width=True):
    ibm_token = os.environ.get("IBM_QUANTUM_TOKEN")
    
    if not ibm_token:
        st.error(L["error_token"])
    else:
        try:
            with st.spinner(L["working"]):
                service = QiskitRuntimeService(channel="ibm_quantum_platform", token=ibm_token)
                backend = service.backend("ibm_torino")
                
                # Devre oluşturma ve Transpile
                raw_qc = create_grover_circuit(target_number)
                qc_transpiled = transpile(raw_qc, backend=backend)
                
                # Çalıştırma
                sampler = Sampler(backend)
                job = sampler.run([qc_transpiled])
                
                # Sonuçlar
                result = job.result()[0].data.meas.get_counts()
                
                st.subheader(f"📊 {L['results']}")
                st.bar_chart(result)
                
                with st.expander(L["circuit_title"]):
                    # Devre çizimi (Text formatında Streamlit'e uygun)
                    st.text(raw_qc.draw(output='text'))
                    
        except Exception as e:
            st.error(f"Bağlantı Hatası: {e}")

st.divider()
st.caption(L["footer"])
