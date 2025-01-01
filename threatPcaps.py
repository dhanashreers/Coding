# Python code to identify threats from PCAP files based on simple threat signatures.

import pyshark

# Define threat signatures
THREAT_SIGNATURES = {
    "malicious_ips": ["192.168.1.100", "10.0.0.50"],  # Known bad IPs
    "suspicious_ports": [23, 3389, 4444],            # Common ports for threats (e.g., Telnet, RDP)
    "payload_keywords": [b"malware", b"exploit", b"attack"]  # Example payload keywords
}

def analyze_pcap(pcap_file):
    try:
        print(f"Analyzing PCAP file: {pcap_file}\n")
        cap = pyshark.FileCapture(pcap_file)

        for packet in cap:
            try:
                # Check IP traffic
                if "IP" in packet:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst

                    # Check for malicious IPs
                    if src_ip in THREAT_SIGNATURES["malicious_ips"] or dst_ip in THREAT_SIGNATURES["malicious_ips"]:
                        print(f"Threat detected: Malicious IP - Packet #{packet.number}")
                        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}\n")

                # Check ports
                if "TCP" in packet or "UDP" in packet:
                    src_port = int(packet[pkt_type].srcport)
                    dst_port = int(packet[pkt_type].dstport)

                    if src_port in THREAT_SIGNATURES["suspicious_ports"] or dst_port in THREAT_SIGNATURES["suspicious_ports"]:
                        print(f"Threat detected: Suspicious Port - Packet #{packet.number}")
                        print(f"Source Port: {src_port}, Destination Port: {dst_port}\n")

                # Check payloads for keywords
                if hasattr(packet, "data"):
                    payload = bytes.fromhex(packet.data.data.replace(":", ""))
                    for keyword in THREAT_SIGNATURES["payload_keywords"]:
                        if keyword in payload:
                            print(f"Threat detected: Suspicious Payload - Packet #{packet.number}")
                            print(f"Payload contains keyword: {keyword.decode()}\n")

            except AttributeError:
                # Some packets may not have the fields we are looking for
                continue
    except Exception as e:
        print(f"Error analyzing PCAP: {e}")

# Replace with your PCAP file path
pcap_file_path = "network_traffic.pcap"

# Run the analysis
analyze_pcap(pcap_file_path)
