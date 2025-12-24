import streamlit as st
import os
from qiskit import QuantumCircuit, transpile
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler

# 1. Sayfa Konfigürasyonu (Mutlaka en başta olmalı)
st.set_page_config(page_title="Quantum Vault", page_icon="🔐", layout="wide")

# --- 🌍 SABİT SOL MENÜ (SIDEBAR) ---
if 'lang' not in st.session_state:
    st.session_state.lang = "Turkish"

st.sidebar.title("🔐 Quantum Vault")
st.sidebar.markdown("---")

# Dil Seçimi (Sidebar'da sabit)
lang_choice = st.sidebar.selectbox(
    "Dil Seçin / Select Language", 
    ["Turkish", "English"], 
    index=0 if st.session_state.lang == "Turkish" else 1
)
st.session_state.lang = lang_choice

# Senin her gün tekrarlayacağın o özel not
if st.session_state.lang == "Turkish":
    st.sidebar.info("Bu proje, IBM Torino (İtalya) üzerindeki gerçek bir kuantum bilgisayarına bağlanır. Her gün tekrarlayacağım.")
    L = {
        "title": "🔐 Kuantum Arama Portalı",
        "desc": "Grover Algoritması kullanarak 3-qubitlik (0-7 arası) bir sistemde kuantum araması yapın.",
        "select": "Aranacak hedef sayıyı seçin (0-7):",
        "btn": "Kuantum Aramayı Başlat 🚀",
        "working": "İtalya'ya bağlanılıyor, devre hazırlanıyor...",
        "res": "Kuantum Ölçüm Sonuçları",
        "circuit": "Oluşturulan Kuantum Devresi (Grover)",
        "footer": "12. Sınıf Portfolyo Projesi - Pixhelz"
    }
else:
    st.sidebar.info("This project connects to a real quantum computer on IBM Torino (Italy). I will repeat every day.")
    L = {
        "title": "🔐 Quantum Search Portal",
        "desc": "Perform a quantum search in a 3-qubit system (0-7) using Grover's Algorithm.",
        "select": "Select target number to search (0-7):",
        "btn": "Start Quantum Search 🚀",
        "working": "Connecting to Italy, preparing circuit...",
        "res": "Quantum Measurement Results",
        "circuit": "Generated Quantum Circuit (Grover)",
        "footer": "12th Grade Portfolio Project - Pixhelz"
    }

# --- 🛠️ TAM GROVER ALGORİTMASI MANTIĞI ---
def create_full_grover(target):
    qc = QuantumCircuit(3)
    
    # 1. Adım: Süperpozisyon (Tüm ihtimalleri aynı anda oluştur)
    qc.h(range(3))
    
    # 2. Adım: Oracle (Seçilen sayıyı kuantumda işaretle)
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
            
    # 3. Adım: Diffuser (İşaretlenen sayının olasılığını artır)
    qc.h(range(3))
    qc.x(range(3))
    qc.h(2)
    qc.ccx(0, 1, 2)
    qc.h(2)
    qc.x(range(3))
    qc.h(range(3))
    
    qc.measure_all()
    return qc

# --- ANA SAYFA ARAYÜZÜ ---
st.title(L["title"])
st.info(L["desc"])

target_number = st.slider(L["select"], 0, 7, 3)

if st.button(L["btn"], use_container_width=True):
    token = os.environ.get("IBM_QUANTUM_TOKEN")
    if not token:
        st.error("Hata: API Token bulunamadı!")
    else:
        try:
            with st.spinner(L["working"]):
                service = QiskitRuntimeService(channel="ibm_quantum_platform", token=token)
                backend = service.backend("ibm_torino")
                
                # Devreyi Oluştur ve Donanıma Göre Çevir (Transpile)
                raw_qc = create_full_grover(target_number)
                qc_t = transpile(raw_qc, backend=backend)
                
                # IBM Torino'da Çalıştır
                sampler = Sampler(backend)
                job = sampler.run([qc_t])
                result = job.result()[0].data.meas.get_counts()
                
                # Sonuçları Görselleştir
                st.subheader(f"📊 {L['res']}")
                st.bar_chart(result)
                
                with st.expander(L["circuit"]):
                    st.text(raw_qc.draw(output='text'))
                    
        except Exception as e:
            st.error(f"Bağlantı Hatası: {e}")

st.divider()
st.caption(L["footer"])
