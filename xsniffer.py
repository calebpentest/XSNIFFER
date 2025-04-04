#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from scapy.all import (
    sniff, conf, IP, TCP, UDP, 
    DNS, DNSQR, Raw, get_if_list
)
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse 
from colorama import Fore, Style, init
import pyfiglet
from cryptography.fernet import Fernet
import sys
import json
import time
import signal
import socket
import threading
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler

class Config:
    def __init__(self):
        self.api_port = 8080
        self.encryption_key = Fernet.generate_key()
        self.max_packets = 10000
        self.interface = conf.iface if hasattr(conf, 'iface') else None
        self.filter = "tcp or udp or icmp or port 80 or port 443"
        self.banner_font = 'slant'

config = Config()

class SecureNetworkState:
    def __init__(self):
        self.cipher = Fernet(config.encryption_key)
        self.api_calls = []
        self.stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'http': 0,
            'dns': 0,
            'api': 0
        }
        self.lock = threading.Lock()

state = SecureNetworkState()

def pentestBanner():
    init(autoreset=True)
    try:
        banner = pyfiglet.figlet_format("XSNIFFER", font='small')
        print(Fore.RED + banner)
        print(Fore.CYAN + "Advanced Network Sniffer")
        print(Fore.RED + "="*40 + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Banner Error: {e}")
        sys.exit(1)

class PacketEngine:
    @staticmethod
    def process(packet):
        try:
            with state.lock:
                state.stats['total'] += 1

           
            if packet.haslayer(HTTPRequest):
                host = packet[HTTPRequest].Host.decode(errors='replace')
                path = packet[HTTPRequest].Path.decode(errors='replace')
                print(Fore.MAGENTA + f"[HTTP] {packet[IP].src} -> {host}{path}")
                with state.lock:
                    state.stats['http'] += 1

            elif packet.haslayer(DNS) and packet[DNS].qr == 0:
                query = packet[DNSQR].qname.decode(errors='replace')
                print(Fore.CYAN + f"[DNS] Query: {query}")
                with state.lock:
                    state.stats['dns'] += 1

            elif packet.haslayer(TCP) and packet.haslayer(Raw):
                with state.lock:
                    state.stats['tcp'] += 1
                try:
                    load = packet[Raw].load.decode(errors='replace').lower()
                    if any(k in load for k in ['api', 'token', 'json']):
                        state.add_api_call({
                            'time': time.strftime("%H:%M:%S"),
                            'src': packet[IP].src,
                            'dst': packet[IP].dst,
                            'size': len(load)
                        })
                        print(Fore.GREEN + f"[API] {packet[IP].src} -> {packet[IP].dst}")
                        with state.lock:
                            state.stats['api'] += 1
                except Exception:
                    pass

            elif packet.haslayer(UDP):
                with state.lock:
                    state.stats['udp'] += 1

        except Exception as e:
            print(Fore.RED + f"[!] Error: {str(e)}")

class PentestAPI(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(state.stats).encode())

def main():
    pentestBanner()
    api_thread = threading.Thread(
        target=lambda: HTTPServer(('localhost', config.api_port), PentestAPI).serve_forever(),
        daemon=True
    )
    api_thread.start()
    print(Fore.YELLOW + f"[*] API running on port {config.api_port}")

    print(Fore.GREEN + f"\n[+] Starting capture on {config.interface}...")
    try:
        sniff(
            iface=config.interface,
            prn=PacketEngine.process,
            store=False,
            filter=config.filter
        )
    except Exception as e:
        print(Fore.RED + f"[!] Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Stopped by user")
        sys.exit(0)