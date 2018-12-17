import argparse
import re
from scapy.all import *
from scapy.layers import http


def process_packet(pcap):
	if not pcap.haslayer(http.HTTPRequest):
		return
	http_layer = pcap.getlayer(http.HTTPRequest)
	ip_layer = pcap.getlayer(IP)
	method = '{0[Method]}'.format(http_layer.fields)
	host = '{0[Host]}'.format(http_layer.fields)
	payload = pcap[TCP].payload
	payload = str(payload).replace("%40", "@")
	payload_email = re.findall(r'[\w\.-]+@[\w\.-]+&[\w\.-]+=[\w\.-]+[\w\.-]+[\w\.-]',str(payload))

	if method.startswith('POST') and payload_email:
			print('{0[src]} {1[Method]} {1[Host]}{1[Path]}'.format(ip_layer.fields, http_layer.fields))
			print(payload_email)


parser = argparse.ArgumentParser(description="PCAP Parser")
parser.add_argument('-p', "--pcap", help="PCAP file")
args = parser.parse_args()

PCAP_file = args.pcap

try:
	packet = rdpcap(PCAP_file)
except:
	print("Invalid PCAP File")

for pkt in packet:
	process_packet(pkt)
