from scapy.all import (ICMP, Raw, IP, TCP, sr1,sniff)
from collections import Counter

#python ping_chat <dst ip> <msg> - need arg parse

dst_ip = ''
buffer = []
send_to =[]
pkt_counts = Counter()
my_ip = ''

def send_msg(msg):
	
	craft_pkt = IP(dst='dst_ip', src=my_ip)/ICMP()/msg
	success = sr1(craft_pkt,timeout=1)
	
	return True

def display_msg(packet):

	client_ip = packet[0][1].src
	client_mac = packet[0].src
	send_to.append((client_ip,client_mac))
	pkt_counts.update(['sent'])
	msg = str(packet[0][Raw].load, 'utf-8')
	
	return f'[{client_ip} says]: {msg}'

#main
icmp_pkt = sniff(prn=display_msg, filter='icmp')

 