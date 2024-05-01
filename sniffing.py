from scapy.all import sniff
def print_pkt(pkt):
    pkt.show()

subred = "192.168.2.0/24"
f = f"(src net {subred}) or (dst net {subred})"
filter = f'tcp dst host 192.168.2.8 and port 23 and ({f})'
print(filter)
pkt = sniff(filter=f'tcp port 23 and ({f})',prn=print_pkt, count=1)
#pkt = sniff(filter=f'icmp',prn=print_pkt, count=0)
