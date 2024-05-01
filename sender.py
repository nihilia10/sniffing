from scapy.all import IP, TCP, send

a = IP()
a.dst = '192.168.2.8'
b = TCP(dport=23)
p = a/b
send(p)