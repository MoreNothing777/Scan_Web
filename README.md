# Escáner de Red y Ataque DoS
Este proyecto utiliza Streamlit y Scapy para crear una interfaz gráfica que permite escanear una red local y realizar un ataque DoS (Denial of Service) a una dirección IP seleccionada.

<img width="1180" height="724" alt="image" src="https://github.com/user-attachments/assets/3407dbdb-8cac-49f7-afd1-6cae011f9df1" />

## Características
Escaneo de Red: Escanea la red local para detectar dispositivos y obtener sus direcciones IP, MAC y nombres de dispositivos.
Ataque DoS: Permite realizar un ataque DoS a una dirección IP seleccionada utilizando Scapy.
Requisitos
Python 3.7+
Streamlit
Scapy
Pandas
IPAddress
Socket
Time
Subprocess
Platform
Netifaces
Threading

## Código
El código principal se encuentra en app.py y utiliza las siguientes bibliotecas:

**Streamlit**: Para crear la interfaz de usuario.
**Scapy**: Para realizar el escaneo de red y el ataque DoS.
**Pandas**: Para manejar y mostrar los datos del escaneo en una tabla.
**IPAddress**: Para manejar direcciones IP y subredes.
**Socket**: Para resolver nombres de dispositivos.
**Time**: Para manejar tiempos de espera y medir el tiempo de escaneo.
**Subprocess**: Para ejecutar comandos de sistema.
**Platform**: Para detectar el sistema operativo.
**Netifaces**: Para obtener la dirección IP local y la puerta de enlace.
**Threading**: Para manejar el ataque DoS en un hilo separado.

## Funciones Principales
· get_local_ip(): Obtiene la dirección IP local.
· obtener_gateway(): Obtiene la dirección IP de la puerta de enlace.
· ip_list_from_local(prefix_len=24): Genera una lista de direcciones IP en la subred local.
· get_mac_address_scapy(ip, timeout=2): Obtiene la dirección MAC de una IP utilizando Scapy.
· ping_ip(ip, timeout=1000): Realiza un ping a una dirección IP.
· get_mac_from_arp_cache(ip): Obtiene la dirección MAC de una IP desde la caché ARP.
· get_device_name(ip): Obtiene el nombre del dispositivo a partir de su dirección IP.
· scan_network_and_update(prefix_len, use_scapy_flag, arp_timeout): Escanea la red y actualiza la interfaz de usuario con los resultados.
· dos_attack_with_scapy(target_ip, flag): Realiza un ataque DoS a la dirección IP objetivo.

