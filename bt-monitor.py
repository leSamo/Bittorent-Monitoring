"""
    Monitoring of BitTorrent Traffic in LAN
    PDS project 2022/23
    Samuel Olekšák (xoleks00)
"""

from scapy.all import *
from bdecoder import bdecode
import binascii
import socket
import getopt
import sys
from node import Node

# print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

HELP_STRING = """
bt-monitor - script for monitoring of BitTorrent traffic in LAN
Usage:
python3 bt-monitor -pcap <path_to_pcap_file> [-init|-peers|-download|-rtable]
  -init: returns a list of detected bootstrap nodes
  -peers: returns a list of detected neighbors
  -download: returns file info_hash, size, chunks, contributes
  -rtable: returns the routing table of the client
"""

# ----------------
# ARGUMENT PARSING
# ----------------

pcap_file = None
operation = None

cli_arguments = sys.argv[1:]

# getopts expects long options to use two dashes
# add additional dash to the beginning of long options
for i in range(len(cli_arguments)):
    if cli_arguments[i] in ["-pcap", "-init", "-peers", "-download", "-rtable"]:
        cli_arguments[i] = "-" + cli_arguments[i]

try:
    opts, args = getopt.getopt(
        cli_arguments,
        "h",
        ["help", "pcap=", "init", "peers", "download", "rtable"]
    )
except getopt.GetoptError:
    print(HELP_STRING)
    sys.exit(1)

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print(HELP_STRING)
        sys.exit()
    elif opt == '--pcap':
        pcap_file = arg
    elif opt == '--init':
        operation = 'init'
    elif opt == '--download':
        operation = 'download'
    elif opt == '--peers':
        operation = 'peers'
    elif opt == '--rtable':
        operation = 'rtable'
    else:
        eprint('Unknown argument:', opt)
        sys.exit(1)

if pcap_file == None:
    eprint('Missing input file, use -pcap argument')
    sys.exit(1)

# Accepts list of raw packets
# Inspects all DNS packets and returns a list of IPv4 and IPv6 addresses which
# were received inside DNS responses
def getDnsReceivedIps(packets):
    dnsReceivedAddresses = set()
    
    for packet in packets:
        # Check if packet is a DNS response and extract IP address
        if packet.haslayer(DNSRR):
            dns_layer = packet.getlayer(DNSRR)

            for i in range(packet[DNS].ancount):
                 # Check if DNS response contains A (IPv4) or AAAA (IPv6) record
                if dns_layer[i].type == 1 or dns_layer[i].type == 28:
                    ip = dns_layer[i].rdata
                    dnsReceivedAddresses.add(ip)

    return dnsReceivedAddresses

def detectReceivedNodes(packets):
    detectedNodes = set()
    dnsReceivedAddresses = getDnsReceivedIps(packets)

    for packet in packets:
        if UDP in packet:
            obj = {}

            # If a UDP packet fails bdecoding we ignore it
            # because its either malformed or not BT-DHT at all
            try:
                obj, _ = bdecode(bytes(packet[UDP].payload))
            except:
                continue

            # TODO: Check for get_peers command
            if b'a' in obj and b'id' in obj[b'a']:
                dst_ip = packet[IP].dst
                dst_port = packet[UDP].dport
                #id = obj[b'a'][b'id']

                # if bencoding contains bs: 1 or IP address was received by DNS, consider it bootstrap
                if (b'bs' in obj[b'a'] and obj[b'a'][b'bs'] == 1) or dst_ip in dnsReceivedAddresses:
                    detectedNodes.add(Node(b"Unknown", dst_ip, dst_port, True, -1))
                else:
                    detectedNodes.add(Node(b"Unknown", dst_ip, dst_port, False, -1))


            elif (b'r' in obj and b'id' in obj[b'r']):
                src_ip = packet[IP].src
                src_port = packet[UDP].sport
                id = obj[b'r'][b'id']

                for node in detectedNodes:
                    if node.ip_address == src_ip and node.port == src_port:
                        node.id = id
                        break
                    

    return detectedNodes

# accepts two ids in hex format and returns in how many
# bits their prefixes match
def kademlia_distance(node_id1: str, node_id2: str) -> int:
    # convert hex to binary, remove 0b prefix and pad it to 160 bits
    id1 = bin(int(node_id1, 16))[2:].zfill(160)
    id2 = bin(int(node_id2, 16))[2:].zfill(160)
    
    prefix_length = 0

    for i in range(len(id1)):
        if id1[i] == id2[i]:
            prefix_length += 1
        else:
            break
    
    return prefix_length

# ------------------------------
# LOADING PACKETS FROM PCAP FILE
# ------------------------------

try:
    packets = rdpcap(pcap_file)
except Exception as e:
    eprint('Failed to load packets from pcap file', e)
    sys.exit(1)

# ------------------------------------
# BRANCH PROGRAM BY SELECTED OPERATION
# ------------------------------------

if operation == "init":
    receivedNodes = detectReceivedNodes(packets)
    bootstrapNodes = list(filter(lambda node: node.is_bootstrap, receivedNodes))

    print("Detected boostrap nodes:\n")
    print(f"ID                                       Port  IP address")

    for node in bootstrapNodes:
        print(node)

elif operation == "peers":
    packets = rdpcap(pcap_file)
    receivedNodes = detectReceivedNodes(packets)
    print("Detected neighbor nodes:\n")
    print(f"ID                                       Port  IP address")
    for node in receivedNodes:
        print(node)

elif operation == "download":
    pass

elif operation == "rtable":
    # find get peer requests and print id in them
    packets = rdpcap(pcap_file)

    my_ids = []
    transaction_ids = {}
    my_peers = {}

    for (index, packet) in enumerate(packets):
        if UDP in packet:
            obj = {}

            try:
                obj, _ = bdecode(bytes(packet[UDP].payload))
            except:
                #print("Failed parsing bencoding for packet", index)
                continue
            if b'q' in obj and obj[b'q'] == b'get_peers':
                my_id = binascii.hexlify(obj[b'a'][b'id']).decode()
                if not my_id in my_ids:
                    my_ids.append(my_id)
                    transaction_ids[my_id] = [binascii.hexlify(obj[b't']).decode()]
                    my_peers[my_id] = []

                transaction_ids[my_id].append(binascii.hexlify(obj[b't']).decode())
            elif b'y' in obj and obj[b'y'] == b'r':
                trans_id = binascii.hexlify(obj[b't']).decode()
                for my_id in my_ids:
                    transactions = transaction_ids[my_id]

                    if trans_id in transactions:
                        if b'r' in obj and b'nodes' in obj[b'r']:
                            node_list = obj[b'r'][b'nodes']
                            sliced_ids = [node_list[i:i+26] for i in range(0, len(node_list), 26)]

                            nodes = list(map(
                                lambda x: Node(
                                    x[0:20],
                                    socket.inet_ntoa(x[20:24]),
                                    int.from_bytes(x[24:26], byteorder='big'),
                                    False,
                                    kademlia_distance(my_id, binascii.hexlify(x[0:20]).decode())
                                ),
                                sliced_ids
                            ))
                            
                            my_peers[my_id].extend(nodes)

    for peer in my_peers.keys():
        print("\nRouting table of", peer)
        my_peers[peer].sort(key=lambda node: node.distance)

        preivousDistance = -1
        for node in my_peers[peer]:
            if (node.distance > preivousDistance):
                preivousDistance = node.distance
                print("\ndistance", node.distance)
            print(node)
        print()

else:
    eprint('Missing operation, use -init, -peers, -download or -rtable')
    sys.exit(1)
