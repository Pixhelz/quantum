import streamlit as st
import os
from qiskit import QuantumCircuit, transpile
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler

# 1. Sayfa Ayarları
st.set_page_config(page_title="Quantum Music", page_icon="🎵", layout="wide")

# --- 🌍 DİL KONTROLÜ ---
if 'lang' not in st.session_state:
    st.session_state.lang = "Turkish"

texts = {
    "Turkish": {
        "title": "🎵 Kuantum Melodi Oluşturucu",
        "info": "İtalya'daki atomik titreşimleri kuantum olasılıklarıyla müziğe dönüştürün.",
        "btn": "Kuantum Besteyi Başlat 🚀",
        "working": "İtalya'daki işlemciye (IBM Torino) bağlanılıyor...",
        "success": "Kuantum Besteniz Hazır!",
        "note_label": "Nota",
        "error_token": "Hata: IBM_QUANTUM_TOKEN bulunamadı!"
    },
    "English": {
        "title": "🎵 Quantum Melody Composer",
        "info": "Convert atomic vibrations in Italy into music using quantum probabilities.",
        "btn": "Start Quantum Composition 🚀",
        "working": "Connecting to the processor in Italy (IBM Torino)...",
        "success": "Your Quantum Composition is Ready!",
        "note_label": "Note",
        "error_token": "Error: IBM_QUANTUM_TOKEN not found!"
    }
}

L = texts[st.session_state.lang]

# --- 🎹 NOTA AYARLARI ---
NOTES = {
    "000": "C4 (Do)", "001": "D4 (Re)", "010": "E4 (Mi)", "011": "F4 (Fa)",
    "100": "G4 (Sol)", "101": "A4 (La)", "110": "B4 (Si)", "111": "C5 (Do)"
}

# --- 🛠️ KUANTUM MANTIK ---
def generate_quantum_notes(backend):
    qc = QuantumCircuit(3)
    qc.h(range(3)) # Süperpozisyon: Tüm notalar aynı anda var
    qc.measure_all()
    # Donanım hatasını çözen kritik satır:
    return transpile(qc, backend=backend)

# --- ARAYÜZ ---
st.title(L["title"])
st.write(L["info"])

if st.button(L["btn"], use_container_width=True):
    ibm_token = os.environ.get("IBM_QUANTUM_TOKEN")
    
    if not ibm_token:
        st.error(L["error_token"])
    else:
        try:
            with st.spinner(L["working"]):
                service = QiskitRuntimeService(channel="ibm_quantum_platform", token=ibm_token)
                backend = service.backend("ibm_torino")
                
                # Devreyi donanıma uygun çevir ve çalıştır
                qc_transpiled = generate_quantum_notes(backend)
                sampler = Sampler(backend)
                job = sampler.run([qc_transpiled])
                
                # Sonuçları al
                result = job.result()[0].data.meas.get_counts()
                
                # En yüksek olasılıklı 4 durumu seç
                sorted_notes = sorted(result.items(), key=lambda x: x[1], reverse=True)
                melody_bits = [bit for bit, count in sorted_notes[:4]]
                
                # --- 🎼 SONUÇLARI GÖSTER ---
                st.subheader("🎼 " + L["success"])
                cols = st.columns(4)
                for i, bit in enumerate(melody_bits):
                    with cols[i]:
                        st.metric(label=f"{i+1}. {L['note_label']}", value=NOTES[bit])
                
                # Kuantum Olasılık Grafiği
                st.bar_chart(result)
                
        except Exception as e:
            st.error(f"Bağlantı Hatası / Connection Error: {e}")

st.divider()
st.caption("Quantum Vault Project - Pixhelz")
