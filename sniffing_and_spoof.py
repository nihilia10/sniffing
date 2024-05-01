from scapy.all import sniff, IP, TCP, send

def change_src_ip(packet):
    print("ORIGINAL")
    packet.show()
    print("--------------------------")
    if packet.haslayer(IP):
        src_ip='192.168.2.6' #default
        packet[IP].src = src_ip
        packet[IP].src = '192.168.2.8'
        
        # Elimina las checksums del paquete IP y TCP para que Scapy las recalcule
        del packet[IP].chksum
        if packet.haslayer(TCP):
            del packet[TCP].chksum
        
        # Muestra el paquete modificado (opcional)
        packet.show()
        send(packet)



subred = "192.168.2.0/24"
filter = f'tcp and port 23 and ((src net {subred}) or (dst net {subred}))'
pkt = sniff(filter=filter,prn=change_src_ip, count=1)
