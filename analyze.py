from scapy.all import *
from bdecoder import bdecode
import binascii
from dataclasses import dataclass
import socket

@dataclass
class Node:
    id: bytes
    ip_address: bytes
    port: bytes

# create an array of dicts { node_id, ip_address, port }

# received array  -> containing nodes which were received from DHT responses
received_nodes = []
#  containing nodes which were queried and at that time they weren't in received array
bootstrap_nodes = []

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

            sliced_ids = list(map(
                lambda x: Node(
                    x[0:40],
                    x[40:48],
                    x[48:52]
                ),
                sliced_ids
            ))

            newObj['r']['nodes'] = sliced_ids

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
        # detect DNS queries for bootstrap nodes

# Load the pcap file
packets = rdpcap('pcap/raw/dht-small.pcapng')

# Print the number of packets in the file
print(f"Number of packets: {len(packets)}")
detectBootstrapNodes(packets)

