# Scan_Web

Este proyecto es una aplicación web interactiva construida con Streamlit que permite escanear una red local para obtener información sobre dispositivos conectados, incluyendo sus direcciones IP, MAC y nombres de host. Además, incluye una funcionalidad para realizar un ataque de denegación de servicio (DoS) a una dirección IP específica.

## Funcionalidades

- **Escaneo de Red Local**: Escanea la red local para identificar dispositivos conectados y recopilar sus direcciones IP, MAC y nombres de host.
- **Ataque DoS**: Permite realizar un ataque de denegación de servicio a una dirección IP seleccionada.

## Requisitos

- Python 3.6+
- Streamlit
- Scapy
- Pandas
- IPAddress
- Socket
- Time
- Subprocess
- Platform
- String
- Random

 ## Escaneo de Red
 
- **get_local_ip()**: Obtiene la IP local del dispositivo.
- **ip_list_from_local(prefix_len=24)**: Genera una lista de direcciones IP en la red local basada en la máscara de subred especificada.
- **get_mac_address_scapy(ip, timeout=2)**: Obtiene la dirección MAC de un dispositivo en la red utilizando Scapy.
- **ping_ip(ip, timeout=1000)**: Realiza un ping a una dirección IP específica.
- **get_mac_from_arp_cache(ip):** Obtiene la dirección MAC de un dispositivo a partir de la caché ARP del sistema.
- **get_device_name(ip)**: Obtiene el nombre del dispositivo a partir de su dirección IP.

## Ataque DoS

- **random_string(length)**: Genera una cadena aleatoria de la longitud especificada.
- **dos_attack_with_scapy(target_ip, duration)**: Realiza un ataque DoS a la dirección IP especificada durante la duración indicada.
