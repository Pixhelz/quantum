import streamlit as st
import os
import matplotlib.pyplot as plt
from qiskit import QuantumCircuit
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler

# --- 1. MOBİL AYARLAR VE SAYFA YAPISI ---
st.set_page_config(
    page_title="Quantum Vault", 
    page_icon="🔐", 
    layout="centered" # Mobil ve tabletlerde daha iyi odaklanma sağlar
)

# Dil Hafızası
if 'lang' not in st.session_state:
    st.session_state.lang = "Türkçe"

def change_lang():
    st.session_state.lang = st.session_state.lang_selector

# Sidebar - Mobil kullanıcılar burayı sol üst menüden açar
st.sidebar.selectbox("Dil / Language", ["Türkçe", "English"], 
                    index=0 if st.session_state.lang == "Türkçe" else 1,
                    on_change=change_lang, key="lang_selector")

T = {
    "Türkçe": {
        "title": "🔐 Quantum Vault",
        "desc": "IBM Torino (İtalya) Kuantum İşlemcisi üzerinde çalışan etkileşimli arama portalı.",
        "slider": "Aranacak sayı (0-7):",
        "fire_btn": "Kuantum İşlemciyi Ateşle 🚀",
        "circuit_header": "Üretilen Kuantum Devresi:",
        "recovery_header": "📊 Veri Analizi",
        "job_label": "Job ID girin:",
        "fetch_btn": "Sonucu Getir",
        "success": "Bağlantı Başarılı!",
        "about": "Bu proje bir lise öğrencisi tarafından geliştirilmiştir."
    },
    "English": {
        "title": "🔐 Quantum Vault",
        "desc": "Interactive search portal running on IBM Torino (Italy) Quantum Hardware.",
        "slider": "Number to search (0-7):",
        "fire_btn": "Fire Quantum Processor 🚀",
        "circuit_header": "Generated Quantum Circuit:",
        "recovery_header": "📊 Data Analysis",
        "job_label": "Enter Job ID:",
        "fetch_btn": "Fetch Result",
        "success": "Connection Successful!",
        "about": "This project was developed by a highschool student."
    }
}
txt = T[st.session_state.lang]

# --- 2. GÜVENLİ IBM BAĞLANTISI (Render Uyumlu) ---
def get_ibm_service():
    # Render üzerindeki Environment Variable'ı oku
    ibm_token = os.environ.get("IBM_QUANTUM_TOKEN")
    try:
        if ibm_token:
            return QiskitRuntimeService(channel="ibm_quantum", token=ibm_token)
        else:
            # Yerel bilgisayarda çalışırken kayıtlı hesabı kullanır
            return QiskitRuntimeService()
    except Exception as e:
        st.error(f"Bağlantı Hatası / Connection Error: {e}")
        return None

# --- 3. KUANTUM MOTORU ---
def build_quantum_search_engine(target_number):
    qc = QuantumCircuit(3)
    qc.h(range(3))
    binary_target = format(target_number, '03b')
    for i, bit in enumerate(reversed(binary_target)):
        if bit == '0': qc.x(i)
    qc.h(2); qc.mcx([0, 1], 2); qc.h(2)
    for i, bit in enumerate(reversed(binary_target)):
        if bit == '0': qc.x(i)
    qc.h(range(3)); qc.x(range(3))
    qc.h(2); qc.mcx([0, 1], 2); qc.h(2)
    qc.x(range(3)); qc.h(range(3))
    qc.measure_all()
    return qc

# --- 4. ARAYÜZ ---
st.title(txt["title"])
st.info(txt["desc"])

# Mobilde daha rahat kullanılması için sütunlara bölelim
col1, col2 = st.columns([2, 1])
with col1:
    target_val = st.slider(txt["slider"], 0, 7, 3)
with col2:
    st.write("") # Boşluk
    run_button = st.button(txt["fire_btn"], use_container_width=True)

if run_button:
    service = get_ibm_service()
    if service:
        backend = service.backend("ibm_torino")
        circuit = build_quantum_search_engine(target_val)
        pm = generate_preset_pass_manager(optimization_level=1, backend=backend)
        isa_circuit = pm.run(circuit)
        
        sampler = Sampler(backend)
        job = sampler.run([isa_circuit])
        st.success(f"ID: {job.job_id()}")
        # Mobilde devre şeması çok genişleyebilir, bu yüzden genişliği kısıtlıyoruz
        st.subheader(txt["circuit_header"])
        st.text(str(circuit.draw(output='text')))

# --- 5. SONUÇ SORGULAMA ---
st.divider()
st.subheader(txt["recovery_header"])
job_id_input = st.text_input(txt["job_label"])

if st.button(txt["fetch_btn"], use_container_width=True):
    service = get_ibm_service()
    if service:
        try:
            job = service.job(job_id_input)
            status = str(job.status())
            if "DONE" in status.upper() or "COMPLETED" in status.upper():
                counts = job.result()[0].data.meas.get_counts()
                st.success(txt["success"])
                st.bar_chart(counts)
            else:
                st.warning(f"Status: {status}")
        except Exception as e:
            st.error(f"Error: {e}")

st.sidebar.caption(txt["about"])