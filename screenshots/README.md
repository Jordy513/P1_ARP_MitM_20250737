# Capturas de pantalla — ARP MitM

Capturas del laboratorio en orden de demostración.

| Archivo | Descripción |
|---------|-------------|
| `01_topologia.png` | Topología en PNETLab con nombre y matrícula visibles |
| `02_arp_antes.png` | Caché ARP legítima en la víctima antes del ataque |
| `03_ataque_ejecutandose.png` | Script corriendo — resolución de MACs y contador de paquetes |
| `04_arp_envenenada.png` | Caché ARP de la víctima con la MAC de Kali en lugar de R1 |
| `05_trafico_interceptado.png` | `tcpdump` en Kali mostrando el tráfico de la víctima en tránsito |
| `06_contramedida_aplicada.png` | DAI configurado en SW2 |
| `07_arp_restaurada.png` | Caché ARP restaurada automáticamente tras `Ctrl+C` |
