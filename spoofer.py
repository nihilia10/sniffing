from scapy.all import IP, TCP, send

def send_custom_packet(dst_ip, dst_port, src_ip):
    # Create an IP packet with the specified source and destination IP addresses
    ip_layer = IP(src=src_ip, dst=dst_ip)
    
    # Create a TCP layer with the specified destination port
    tcp_layer = TCP(dport=dst_port)
    
    # Stack the layers together to form a complete packet
    packet = ip_layer / tcp_layer
    
    # Send the packet out
    send(packet)

# Parameters for the packet
destination_ip = "192.168.1.10"  # Destination IP address (modify as needed)
destination_port = 80           # Destination port (modify as needed)
source_ip = "10.0.0.1"          # New source IP address (arbitrary value)

# Send the packet
send_custom_packet(destination_ip, destination_port, source_ip)
