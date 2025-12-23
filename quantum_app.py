import streamlit as st
import os
from qiskit import QuantumCircuit
from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler

# --- 1. SAYFA VE MOBİL AYARLARI ---
st.set_page_config(page_title="Quantum Vault", page_icon="🔐", layout="centered")

# Dil Hafızası (Session State)
if 'lang' not in st.session_state:
    st.session_state.lang = "Türkçe"

def change_lang():
    st.session_state.lang = st.session_state.lang_selector

# Sidebar Dil Seçimi
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
        "about": "Bu proje bir 12. sınıf öğrencisi tarafından geliştirilmiştir."
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
        "about": "This project was developed by a 12th-grade student."
    }
}
txt = T[st.session_state.lang]

# --- 2. GÜVENLİ IBM BAĞLANTISI (Hata Giderilmiş Versiyon) ---
def get_ibm_service():
    ibm_token = os.environ.get("IBM_QUANTUM_TOKEN")
    try:
        if ibm_token:
            # HATA BURADAYDI: Kanal ismini güncelledik
            return QiskitRuntimeService(channel="ibm_quantum_platform", token=ibm_token)
        else:
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

# --- 4. ANA ARAYÜZ ---
st.title(txt["title"])
st.info(txt["desc"])

col1, col2 = st.columns([2, 1])
with col1:
    target_val = st.slider(txt["slider"], 0, 7, 3)
with col2:
    st.write("") 
    # Benzersiz key ekledik: "fire_button_unique"
    run_button = st.button(txt["fire_btn"], use_container_width=True, key="fire_button_unique")

if run_button:
    service = get_ibm_service()
    if service:
        with st.spinner('🚀 Processing...'):
            backend = service.backend("ibm_torino")
            circuit = build_quantum_search_engine(target_val)
            pm = generate_preset_pass_manager(optimization_level=1, backend=backend)
            isa_circuit = pm.run(circuit)
            sampler = Sampler(backend)
            job = sampler.run([isa_circuit])
            st.success(f"ID: {job.job_id()}")
            st.subheader(txt["circuit_header"])
            st.text(str(circuit.draw(output='text')))

# --- 5. SONUÇ SORGULAMA ---
st.divider()
st.subheader(txt["recovery_header"])
job_id_input = st.text_input(txt["job_label"], key="job_id_input_unique")

# Benzersiz key ekledik: "fetch_button_unique"
if st.button(txt["fetch_btn"], use_container_width=True, key="fetch_button_unique"):
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
