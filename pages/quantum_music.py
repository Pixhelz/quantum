import streamlit as st
import os
from qiskit import QuantumCircuit
from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2 as Sampler

# Sayfa Ayarları
st.set_page_config(page_title="Quantum Music Generator", page_icon="🎵")

st.title("🎵 Quantum Melody Composer")
st.write("IBM Torino işlemcisindeki atomik titreşimleri müziğe dönüştürün.")

# --- 🎹 NOTA AYARLARI ---
# 3 Qubit = 2^3 = 8 Farklı Durum (Nota)
NOTES = {
    "000": "C4 (Do)",
    "001": "D4 (Re)",
    "010": "E4 (Mi)",
    "011": "F4 (Fa)",
    "100": "G4 (Sol)",
    "101": "A4 (La)",
    "110": "B4 (Si)",
    "111": "C5 (Do - İnce)"
}

# --- 🛠️ FONKSİYONLAR ---
def create_music_circuit():
    """Tüm notaları süperpozisyona sokan devre"""
    qc = QuantumCircuit(3)
    qc.h(range(3))  # Hadamard kapısı ile tüm notalar aynı anda var olur
    qc.measure_all()
    return qc

# --- 🖥️ ARAYÜZ ---
st.info("Bu modül, kuantum rastgeleliğini kullanarak 4 notalık özgün bir melodi oluşturur.")

if st.button("Kuantum Besteyi Başlat 🚀", use_container_width=True):
    ibm_token = os.environ.get("IBM_QUANTUM_TOKEN")
    
    if not ibm_token:
        st.error("API Token bulunamadı! Lütfen Render panelinden ayarları kontrol et.")
    else:
        try:
            with st.spinner("İtalya'daki kuantum işlemcisine bağlanılıyor..."):
                service = QiskitRuntimeService(channel="ibm_quantum_platform", token=ibm_token)
                backend = service.backend("ibm_torino")
                
                # Devreyi oluştur ve gönder
                qc = create_music_circuit()
                sampler = Sampler(backend)
                job = sampler.run([qc])
                
                st.write(f"İşlem Kimliği (Job ID): `{job.job_id()}`")
                
                # Sonuçları al
                result = job.result()[0].data.meas.get_counts()
                
                # En yüksek olasılıklı 4 notayı melodiye çevir
                # (Kuantum gürültüsü ve olasılık her seferinde farklı bir beste sunar)
                sorted_notes = sorted(result.items(), key=lambda x: x[1], reverse=True)
                melody_bits = [bit for bit, count in sorted_notes[:4]]
                
                # --- 🎼 SONUÇ EKRANI ---
                st.subheader("🎼 Kuantum Besteniz")
                cols = st.columns(4)
                for i, bit in enumerate(melody_bits):
                    with cols[i]:
                        st.metric(label=f"{i+1}. Nota", value=NOTES[bit])
                
                st.success("Beste tamamlandı! Bu melodi az önce İtalya'daki bir atomun durumuna göre şekillendi.")
                
                # Olasılık Grafiği
                st.bar_chart(result)
                
        except Exception as e:
            st.error(f"Bağlantı hatası: {e}")

# Alt Bilgi
st.divider()
st.caption("Quantum Vault Project - Powered by IBM Quantum & Qiskit")