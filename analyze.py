from scapy.all import *
from bdecoder import bdecode
import binascii
from dataclasses import dataclass
import socket
import getopt
import sys
import csv

# BOOTSTRAP NODES:
# y: q (message type: request)
# a: { bs: 1 }
# t: XXXX (transaction id)
# bootstrap node is the IP and port

#print("Bootstrap nodes detected using DNS and a list of well known bootstrap nodes:")
#print("Bootstrap nodes detected using DNS and keyword detection:")

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

# ----------------
# ARGUMENT PARSING
# ----------------

pcap_file = None
use_debug_logging = False
operation = None

cli_arguments = sys.argv[1:]

# getopts expects long options to use two dashes
# add additional dash to the beginning of long options
for i in range(len(cli_arguments)):
    if cli_arguments[i] in ["-pcap", "-init", "-peers", "-download", "-rtable"]:
        cli_arguments[i] = "-" + cli_arguments[i]

try:
    opts, args = getopt.getopt(cli_arguments, "hv", ["help", "verbose", "pcap=", "init", "peers", "download"])
except getopt.GetoptError:
    eprint('TODO: Help')
    sys.exit(1)

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        eprint('TODO: Help')
        sys.exit()
    if opt == '-v' or opt == '--verbose':
        use_debug_logging = True
    elif opt == '--pcap':
        pcap_file = arg
    elif opt == '--init':
        operation = 'init'
    elif opt == '--download':
        operation = 'download'
    elif opt == '--peers':
        operation = 'peers'
    else:
        eprint('Unknown argument:', opt)
        sys.exit(1)

if pcap_file == None:
    eprint('Missing input file, use -pcap argument')
    sys.exit(1)

@dataclass
class Node:
    id: bytes
    ip_address: bytes
    port: bytes
    is_bootstrap: bool

    def __repr__(self):
        id = "Unknown (did not respond)" if self.id == "Unknown" else binascii.hexlify(self.id).decode()
        return f"{id.ljust(40)} {str(self.port).ljust(5)} {self.ip_address}";

def detectNodes(packets):
    detectedNodes = []

    for (index, packet) in enumerate(packets):
        if UDP in packet:
            obj = {}

            try:
                obj = bdecode(bytes(packet[UDP].payload))[0]
            except:
                #print("Failed parsing bencoding for packet", index)
                continue

            print(obj)

            # TODO: Maybe deduplicate?
            # TODO: Check for get_peers command
            if b'a' in obj and b'id' in obj[b'a']:
                dst_ip = packet[IP].dst
                dst_port = packet[UDP].dport
                #id = obj[b'a'][b'id']

                if b'bs' in obj[b'a'] and obj[b'a'][b'bs'] == 1:
                    detectedNodes.append(Node("Unknown", dst_ip, dst_port, True))
                else:
                    detectedNodes.append(Node("Unknown", dst_ip, dst_port, False))


            elif (b'r' in obj and b'id' in obj[b'r']):
                src_ip = packet[IP].src
                src_port = packet[UDP].sport
                id = obj[b'r'][b'id']
            
                for node in detectedNodes:
                    if node.ip_address == src_ip and node.port == src_port:
                        node.id = id
                        break
                    

    return detectedNodes


if operation == "init":
    packets = rdpcap(pcap_file)
    detectedNodes = detectNodes(packets)
    bootstrapNodes = list(filter(lambda node: node.is_bootstrap, detectedNodes))
    print("Detected boostrap nodes:\n")
    print(f"ID                                       Port  IP address")
    for node in bootstrapNodes:
        print(node)
elif operation == "peers":
    packets = rdpcap(pcap_file)
    detectedNodes = detectNodes(packets)
    print("Detected neighbor nodes:\n")
    print(f"ID                                       Port  IP address")
    for node in detectedNodes:
        print(node)
else:
    eprint('Missing operation, use -init, -peers or -download')
    sys.exit(1)

"""
@dataclass
class Node:
    id: bytes
    ip_address: bytes
    port: bytes

# create an array of dicts { node_id, ip_address, port }

# nodes which were received from DHT responses
received_nodes = []
# nodes which were queried and at that time they weren't in received array
bootstrap_nodes = []
# nodes which were queried
contacted_nodes = []

def parseBt(payload):
    newObj = {}

    for key, value in payload.items():
        newKey = None;
        newValue = None;
        try:
            newKey = key.decode()
        except Exception:
            newKey = binascii.hexlify(key).decode()
        
        if (type(value) is int):
            newValue = value
        elif (type(value) is dict):
            newValue = parseBt(value)
        else:
            try:
                newValue = value.decode()
            except Exception:
                newValue = binascii.hexlify(value).decode()
        
        newObj[newKey] = newValue

    if 'ip' in newObj:
        ipAddr = binascii.unhexlify(newObj['ip'])[:4]
        port = binascii.unhexlify(newObj['ip'])[4:]

        newObj['ip'] = socket.inet_ntoa(ipAddr)
        newObj['port'] =  int.from_bytes(port, byteorder='big')

    if 'r' in newObj:
        if 'nodes' in newObj['r']:
            ids = newObj['r']['nodes']
            sliced_ids = [ids[i:i+52] for i in range(0, len(ids), 52)]

            nodes = list(map(
                lambda x: Node(
                    x[0:40],
                    x[40:48],
                    x[48:52]
                ),
                sliced_ids
            ))

            for node in nodes:
                if node.id not in received_nodes:
                    received_nodes.append(node.id)

            newObj['r']['nodes'] = nodes

    if 'q' in newObj and newObj['q'] == 'get_peers':
        pass

    return newObj;

def prettyPrintBt(payload, indentSize = 0):
    for key, value in payload.items():
        try:
            print("  " * indentSize, key.decode(), end=": ")
        except Exception:
            print("  " * indentSize, binascii.hexlify(key).decode(), end=": ")
        
        if (type(value) is int):
            print(value)
        elif (type(value) is dict):
            print("\n", end="")
            prettyPrintBt(value, indentSize + 1)
        else:
            try:
                print(value.decode())
            except Exception:
                print(binascii.hexlify(value).decode())

# start from the begining and note which nodes are delivered
# if request/response is from a delivered node, then it's not a bootstrap node
def detectBootstrapNodes(packets):
    for (index, packet) in enumerate(packets):
        if UDP in packet:
            #del packet[UDP]
            #del packet[UDP]
            print("UDP packet", index);
            obj = bdecode(bytes(packet[UDP].payload))[0]
            prettyPrintBt(obj)
            print(parseBt(obj))

    print("Received nodes:", received_nodes)
        # detect DNS queries for bootstrap nodes

# Load the pcap file
packets = rdpcap('pcap/raw/dht-small.pcapng')

# Print the number of packets in the file
print(f"Number of packets: {len(packets)}")
detectBootstrapNodes(packets)

"""