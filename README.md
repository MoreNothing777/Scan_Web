# Scan_Web

Este proyecto es una aplicación web interactiva construida con Streamlit que permite escanear una red local para obtener información sobre dispositivos conectados, incluyendo sus direcciones IP, MAC y nombres de host. Además, incluye una funcionalidad para realizar un ataque de denegación de servicio (DoS) a una dirección IP específica.

<img width="1163" height="828" alt="image" src="https://github.com/user-attachments/assets/41e995e4-361d-4f84-a92a-8d5ef8677bac" />


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
- **ip_list_from_local()**: Genera una lista de direcciones IP en la red local basada en la máscara de subred especificada.
- **get_mac_address_scapy()**: Obtiene la dirección MAC de un dispositivo en la red utilizando Scapy.
- **ping_ip()**: Realiza un ping a una dirección IP específica.
- **get_mac_from_arp_cache():** Obtiene la dirección MAC de un dispositivo a partir de la caché ARP del sistema.
- **get_device_name()**: Obtiene el nombre del dispositivo a partir de su dirección IP.

## Ataque DoS

- **random_string()**: Genera una cadena aleatoria de la longitud especificada.
- **dos_attack_with_scapy()**: Realiza un ataque DoS a la dirección IP especificada durante la duración indicada.
