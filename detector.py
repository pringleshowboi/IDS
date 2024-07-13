from scapy.all import *
import pandas as pd
import alert  # Import the alert module to send alerts

def load_rules(filepath):
    rules = []
    with open(filepath, 'r') as file:
        for line in file:
            if not line.startswith('#') and line.strip():
                rules.append(line.strip().split())
    return rules

def match_packet(packet, rules):
    for rule in rules:
        protocol, src_ip, src_port, dst_ip, dst_port, pattern = rule
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if packet[IP].src == src_ip and packet[IP].dst == dst_ip:
                if (packet[IP].sport == int(src_port) and packet[IP].dport == int(dst_port)) or \
                    (packet[IP].sport == int(dst_port) and packet[IP].dport == int(src_port)):
                    if pattern in str(packet.payload):
                        return True
    return False

def packet_callback(packet):
    rules = load_rules('rules.txt')
    if match_packet(packet, rules):
        alert.send_alert(f"Suspicious activity detected: {packet.summary()}")

def start_sniffing():
    print("Starting IDS...")
    # Change "YOUR_INTERFACE" to your actual network interface name
    sniff(prn=packet_callback, store=0, filter="ip", iface="Ethernet")

if __name__ == "__main__":
    start_sniffing()
