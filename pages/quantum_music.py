import streamlit as st
import os
import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler

# 1. Sayfa Konfigürasyonu
st.set_page_config(page_title="Quantum Music", page_icon="🎵", layout="wide")

# --- 🌍 DİL SENKRONİZASYONU ---
if 'lang' not in st.session_state:
    st.session_state.lang = "Turkish"

texts = {
    "Turkish": {
        "title": "🎵 Kuantum Melodi Oluşturucu",
        "info": "İtalya'daki atomik titreşimleri kuantum olasılıklarıyla müziğe dönüştürün.",
        "btn": "Bestele ve Çal 🎹",
        "working": "İtalya'daki işlemciden notalar besteleniyor...",
        "audio_msg": "Kuantum Besteniz Hazır (Dinlemek için oynatın):",
        "footer": "Quantum Vault Project - Pixhelz"
    },
    "English": {
        "title": "🎵 Quantum Melody Composer",
        "info": "Convert atomic vibrations in Italy into music using quantum probabilities.",
        "btn": "Compose & Play 🎹",
        "working": "Composing notes from processor in Italy...",
        "audio_msg": "Your Quantum Composition is Ready (Play to listen):",
        "footer": "Quantum Vault Project - Pixhelz"
    }
}
L = texts[st.session_state.lang]

# --- 🎹 NOTA & FREKANS AYARLARI ---
FREQS = {
    "000": 261.63, # Do
    "001": 293.66, # Re
    "010": 329.63, # Mi
    "011": 349.23, # Fa
    "100": 392.00, # Sol
    "101": 440.00, # La
    "110": 493.88, # Si
    "111": 523.25  # Do (İnce)
}

# --- 🔊 SES ÜRETME MANTIĞI ---
def create_tone(freq, duration=0.7):
    sample_rate = 44100
    t = np.linspace(0, duration, int(sample_rate * duration), False)
    # Temiz bir sinüs dalgası (Nota sesi)
    tone = np.sin(freq * t * 2 * np.pi)
    return tone

# --- MÜZİK ARAYÜZÜ ---
st.title(L["title"])
st.write(L["info"])

if st.button(L["btn"], use_container_width=True):
    token = os.environ.get("IBM_QUANTUM_TOKEN")
    if not token:
        st.error("Token bulunamadı!")
    else:
        try:
            with st.spinner(L["working"]):
                service = QiskitRuntimeService(channel="ibm_quantum_platform", token=token)
                backend = service.backend("ibm_torino")
                
                # 3-Qubit Süperpozisyon Devresi
                qc = QuantumCircuit(3)
                qc.h(range(3))
                qc.measure_all()
                
                # Donanım Uyumluluğu (Transpile)
                qc_t = transpile(qc, backend=backend)
                
                # Çalıştır
                sampler = Sampler(backend)
                job = sampler.run([qc_t])
                result = job.result()[0].data.meas.get_counts()
                
                # En yüksek olasılıklı ilk 4 notayı al
                top_notes = sorted(result.items(), key=lambda x: x[1], reverse=True)[:4]
                
                # Ses Verisini Birleştir
                full_audio = np.array([])
                for bit, count in top_notes:
                    tone = create_tone(FREQS[bit])
                    full_audio = np.append(full_audio, tone)
                
                # --- SONUÇLARI GÖSTER ---
                st.success(L["audio_msg"])
                st.audio(full_audio, sample_rate=44100)
                
                st.bar_chart(result)
                
        except Exception as e:
            st.error(f"Hata: {e}")

st.divider()
st.caption(L["footer"])
