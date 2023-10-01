# Importing necessary modules
from scapy.all import *
import ipaddress

# List of common ports to be scanned
ports = [25,80,53,443,445,8080,8443]

# Function for performing SYN scan
def SynScan(host):
    # Sending SYN packets to specified ports and capturing responses
    ans,unans = sr(
        IP(dst=host)/  # Create an IP packet with destination host
        TCP(sport=33333,dport=ports,flags="S")  # Create a TCP packet with SYN flag set
        ,timeout=2,verbose=0)  # Set timeout for responses, and suppress output

    # Print a message indicating the host being scanned
    print("Open ports at %s:" % host)

    # Iterate through the received responses
    for (s,r,) in ans:
        # Check if it's a SYN-ACK response
        if s[TCP].dport == r[TCP].sport and r[TCP].flags=="SA":
            # If so, print the port number
            print(s[TCP].dport)

# Function for performing DNS scan
def DNSScan(host):
    # Sending a DNS query and capturing responses
    ans,unans = sr(
        IP(dst=host)/  # Create an IP packet with destination host
        UDP(dport=53)/  # Create a UDP packet for DNS on port 53
        DNS(rd=1,qd=DNSQR(qname="google.com"))  # Construct a DNS query for google.com
        ,timeout=2,verbose=0)  # Set timeout for responses, and suppress output

    # Check if there are responses and if they contain a UDP layer
    if ans and ans[UDP]:
        # If so, print a message indicating a DNS server was found
        print("DNS Server at %s"%host)

# Prompt user for an IP address
host = input("Enter IP Address: ")

# Try to create an ip_address object from the user input
try:
    ipaddress.ip_address(host)
except:
    # If not a valid IP address, print an error message and exit
    print("Invalid address")
    exit(-1)

# Perform SYN scan on the specified host
SynScan(host)

# Perform DNS scan on the specified host
DNSScan(host)
