# NetMaster Suite - Advanced Network Tool

NetMaster Suite adalah aplikasi GUI berbasis Python yang menyediakan berbagai alat untuk analisis dan manipulasi jaringan.  Aplikasi ini mencakup fitur-fitur seperti penemuan perangkat, ARP spoofing (NetCut), packet sniffing, serangan denial-of-service (DoS), dan analisis file PCAP.

## Peringatan

**PENTING:** Beberapa fitur dalam aplikasi ini, seperti ARP spoofing dan serangan DoS, dapat mengganggu jaringan dan berpotensi ilegal jika digunakan tanpa izin. Gunakan aplikasi ini dengan hati-hati dan bertanggung jawab, hanya pada jaringan yang Anda miliki atau memiliki izin untuk diuji.

## Prasyarat

Sebelum menjalankan NetMaster Suite, pastikan Anda telah menginstal Python 3 dan package-package berikut ini:

*   `tkinter`:  Biasanya sudah terinstal dengan Python.
*   `scapy`: Untuk manipulasi paket jaringan.
*   `python-nmap`: Untuk pemindaian port menggunakan Nmap.
*   `matplotlib`: Untuk visualisasi data.
*   `requests`: Untuk membuat permintaan HTTP (misalnya, untuk mendapatkan vendor MAC address).

Anda dapat menginstal semua dependensi menggunakan pip:

```bash
pip install scapy python-nmap matplotlib requests
