#Importing the necessary modules

import logging
import subprocess

#This will suppress all messages that have a lower level of seriousness than error messages, while running or loading Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)


try:
    from scapy.all import *

except ImportError:
    print ("Scapy package for Python is not installed on your system.")
    print ("Get it from https://pypi.python.org/pypi/scapy and try again.")
    sys.exit()
    


#message to be root
print ("\n! Make sure to run this program as ROOT !\n")

#Setting network interface in promiscuous mode

net_iface = raw_input("[!] Enter the interface on which to run the sniffer (like 'eth1'): ")

subprocess.call(["ifconfig", net_iface, "promisc"], stdout=None, stderr=None, shell=False)

print ("\nInterface %s was set to PROMISC mode." % net_iface)
print

#Asking the user for the number of packets to sniff (the "count" parameter)
pkt_to_sniff = raw_input("Enter the number of packets to capture (0 is infinity): ")

#Considering the case when the user enters 0 (infinity)
if int(pkt_to_sniff) != 0:
    print ("\nThe program will capture %d packets." % int(pkt_to_sniff))
    print
elif int(pkt_to_sniff) == 0:
    print ("\nThe program will capture packets until the timeout expires.")
    print


#Asking the user for the time interval to sniff (the "timeout" parameter)
time_to_sniff = raw_input("* Enter the number of seconds to run the capture: ")

#Handling the value entered by the user
if int(time_to_sniff) != 0:
    print ("\nThe program will capture packets for %d seconds." % int(time_to_sniff))


## Create a Packet Count var
packetNumber = 0

## Define our Custom Action function
def packetNum(packet):
    global packetNumber
    packetNumber += 1
    return "Packet #%s:%s" % (packetNumber, packet.summary())


#Asking the user for any protocol filter he might want to apply to the sniffing process
proto_sniff = raw_input("* Enter the protocol to filter by (0 is all): ")


#Considering the case when the user enters 0 (all)
if proto_sniff == "all":
    print ("\nThe program will capture all protocols.")
	# Setup sniff without filter
    sniff(iface=net_iface, prn=packetNum, count=int(pkt_to_sniff), timeout=int(time_to_sniff))
else:
	print("\nThe program will capture %s protocol." % str(proto_sniff))
	## Setup sniff with filter
	sniff(iface=net_iface, prn=packetNum,filter=proto_sniff, count=int(pkt_to_sniff), timeout=int(time_to_sniff))
