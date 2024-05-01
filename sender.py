from scapy.all import IP, ICMP, send

a = IP()
a.dst = '192.168.2.8'
b = ICMP()
p = a/b
print(p)
send(p)