from scapy.all import *
from scapy.layers.http import HTTP
import csv

def process_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    
    extracted_data = []

    for packet in packets:
        # Extract timestamp
        timestamp = packet.time
        
        # Extract source and destination IP addresses
        src_ip = packet[IP].src if IP in packet else None
        dst_ip = packet[IP].dst if IP in packet else None
        
        # Extract source and destination ports
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
            flags = packet[TCP].sprintf('%flags%')
            
            # Check for HTTP in TCP payload
            if packet[TCP].payload and HTTP in packet[TCP].payload:
                protocol = "HTTP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
            flags = None
        elif ICMP in packet:
            src_port = None
            dst_port = None
            protocol = "ICMP"
            flags = None
        elif ARP in packet:
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            src_port = None
            dst_port = None
            protocol = "ARP"
            flags = None
        else:
            src_port = None
            dst_port = None
            protocol = "Other"
            flags = None
        
        # Extract length
        if TCP in packet:
            length = len(packet[TCP])
        elif UDP in packet:
            length = len(packet[UDP])
        elif ICMP in packet:
            length = len(packet[ICMP])
        elif HTTP in packet:
            length = len(packet[HTTP])
        else:
            length = len(packet)
            
        # Append the extracted data to the list
        extracted_data.append({
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length,
            'flags_A': 'FALSE',
            'flags_ACK': 'FALSE',
            'flags_Echo Request': 'FALSE',
            'flags_FA': 'FALSE',
            'flags_FIN': 'FALSE',
            'flags_PA': 'FALSE',
            'flags_S': 'FALSE',
            'flags_SA': 'FALSE',
            'flags_SYN': 'FALSE',
            'protocol_ICMP': 'FALSE',
            'protocol_TCP': 'FALSE',
            'protocol_UDP': 'FALSE'
        })

    return extracted_data

# Save the extracted data to a CSV fileS
def save_to_csv(data, csv_file):
    with open(csv_file, 'w', newline='') as file:
        fieldnames = [
            'src_ip', 'dst_ip', 'src_port', 'dst_port', 'length',
            'flags_A', 'flags_ACK', 'flags_Echo Request', 'flags_FA',
            'flags_FIN', 'flags_PA', 'flags_S', 'flags_SA', 'flags_SYN',
            'protocol_ICMP', 'protocol_TCP', 'protocol_UDP'
        ]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        
        writer.writeheader()
        
        for row in data:
            writer.writerow(row)

if _name_ == "_main_":
    pcap_file = "packets1.pcap"
    csv_file = "extracted_data.csv"
    
    extracted_data = process_pcap(pcap_file)
    
    # Save the extracted data to a CSV file
    save_to_csv(extracted_data, csv_file)
    
    print(f"Data has been saved to {csv_file}")