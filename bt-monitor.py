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

def toHex(rawBytes):
    return binascii.hexlify(rawBytes).decode()

# string to be printed when program is run with -h or --help switch
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
    transaction_ids = {}
    dnsReceivedAddresses = getDnsReceivedIps(packets)

    # Inspect all UDP packets
    for packet in packets:
        if UDP in packet:
            bhtPayload = {}

            # If a UDP packet fails bdecoding we ignore it
            # because its either malformed or not BT-DHT at all
            try:
                bhtPayload, _ = bdecode(bytes(packet[UDP].payload))
            except:
                continue

            if b't' in bhtPayload:
                if toHex(bhtPayload[b't']) in transaction_ids:
                    transaction_ids[toHex(bhtPayload[b't'])] += 1
                else:
                    transaction_ids[toHex(bhtPayload[b't'])] = 1

            # handle BT-DHT requests
            if b'a' in bhtPayload and b'id' in bhtPayload[b'a'] and b'q' in bhtPayload and bhtPayload[b'q'] == b'get_peers':
                dst_ip = packet[IP].dst
                dst_port = packet[UDP].dport

                # If bencoding contains { bs: 1 } or IP address was received by DNS, consider it bootstrap
                # Save destination IP address and port without the ID for now
                # ID will be possibly filled out later when response in received
                if (b'bs' in bhtPayload[b'a'] and bhtPayload[b'a'][b'bs'] == 1) or dst_ip in dnsReceivedAddresses:
                    detectedNodes.add(Node("Unknown", dst_ip, dst_port, True, -1))
                else:
                    detectedNodes.add(Node("Unknown", dst_ip, dst_port, False, -1))

            # Handle BT-DHT responses
            elif (b'r' in bhtPayload and b'id' in bhtPayload[b'r']):
                src_ip = packet[IP].src
                src_port = packet[UDP].sport
                id = bhtPayload[b'r'][b'id']

                # Match the received ID to source IP and port in our database
                for node in detectedNodes:
                    if node.ip_address == src_ip and node.port == src_port:
                        node.id = id
                        break
                
                if b'nodes' in bhtPayload[b'r']:
                    node_list = bhtPayload[b'r'][b'nodes']
                    sliced_ids = [node_list[i:i+26] for i in range(0, len(node_list), 26)]

                    nodes = list(map(
                        lambda x: Node(
                            x[0:20],
                            socket.inet_ntoa(x[20:24]),
                            int.from_bytes(x[24:26], byteorder='big'),
                            False,
                            -1
                        ),
                        sliced_ids
                    ))

                    for node in nodes:
                        added = False

                        for detectedNode in detectedNodes:
                            if node.ip_address == detectedNode.ip_address and node.port == detectedNode.port:
                                detectedNode.id = node.id
                                added = True
                                break
                        
                        if not added:
                            detectedNodes.add(node)
                            
    return (detectedNodes, transaction_ids)

# accepts two ids in hex format and returns in how many
# bits their prefixes match
def kademlia_distance(node_id1: str, node_id2: str) -> int:
    # convert hex to binary, remove 0b prefix and pad it to 160 bits
    id1 = bin(int(node_id1, 16))[2:].zfill(160)
    id2 = bin(int(node_id2, 16))[2:].zfill(160)
    
    prefix_bit_count = 0

    for i in range(len(id1)):
        if id1[i] != id2[i]:
            break
        else:
            prefix_bit_count += 1
    
    return prefix_bit_count

# goes throught all of the packets and finds the IP address which is sender
# or receiver in most packets, which is most likely client's address
def get_client_ip(packets):
    ip_addresses = {}

    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst

            if src not in ip_addresses:
                ip_addresses[src] = 0

            if dst not in ip_addresses:
                ip_addresses[dst] = 0

            ip_addresses[src] += 1
            ip_addresses[dst] += 1
    
    return max(ip_addresses, key=lambda k: ip_addresses[k])

# ------------------------------
# LOADING PACKETS FROM PCAP FILE
# ------------------------------

try:
    packets = rdpcap(pcap_file)
except Exception as e:
    eprint('Failed to load packets from pcap file', e)
    sys.exit(1)

client_ip = get_client_ip(packets)

# ------------------------------------
# BRANCH PROGRAM BY SELECTED OPERATION
# ------------------------------------

if operation == "init":
    receivedNodes, _ = detectReceivedNodes(packets)
    bootstrapNodes = list(filter(lambda node: node.is_bootstrap, receivedNodes))

    print("Detected boostrap nodes:\n")
    print(f"ID                                       Port  IP address")

    for node in bootstrapNodes:
        print(node)

elif operation == "peers":
    receivedNodes, transaction_ids = detectReceivedNodes(packets)
    print("Detected neighbor nodes:\n")
    print(f"ID                                       Port  IP address")
    for node in receivedNodes:
        print(node)

    connection_count = len([key for key, value in transaction_ids.items() if value > 1])
    print("\nNumber of connections:", connection_count)

elif operation == "download":
    files = {}
    tcp_handshaked_ips = set()
    udp_handshaked_ips = set()

    for (index, packet) in enumerate(packets):
        sport = None
        dport = None
        payload = None

        if IP not in packet:
            continue

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            payload = bytes(packet[TCP].payload)
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            payload = bytes(packet[UDP].payload)

        if UDP in packet:
            # extract connection id from handshake
            # two connection ids, one each way
            # UDP handshake is 88 bytes long (20 uTP + 68 BT)

            # Handle UDP Bittorrent handshake
            if len(payload) >= 88 and payload[20] == 19 and payload[21:40] == b'BitTorrent protocol':
                dst = packet[IP].dst
                src = packet[IP].src
                connection_id = payload[2:4]
                info_hash = payload[48:68]

                if dst == client_ip:
                    udp_handshaked_ips.add((src, sport, connection_id, toHex(info_hash)))

        if TCP in packet:
            if len(payload) > 19:
                protocolNameLength = int(payload[0])
                if protocolNameLength == 19 and payload[1:20] == b'BitTorrent protocol':
                    reserved = payload[20:28]
                    info_hash = payload[28:48]
                    peer_id = payload[48:68]

                    files[toHex(info_hash)] = {
                        "size": 0,
                        "streams": 0,
                        "pieces": [],
                        "contributes": [{
                            "ip": packet[IP].dst,
                            "port": dport,
                            "pieces": []
                        }]
                    }

                    if (packet[IP].dst != client_ip):
                        tcp_handshaked_ips.add((packet[IP].dst, packet[TCP].dport, toHex(info_hash)))

    for handshaked_ip, handshaked_port, info_hash in tcp_handshaked_ips:
        tcp_streams = []
        pieces = set()

        for (packet_index, packet) in enumerate(packets):
            if IP in packet and packet[IP].src == handshaked_ip and TCP in packet and packet[TCP].sport == handshaked_port:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payload = bytes(packet[TCP].payload)

                if len(payload) > 4:
                    message_length = int.from_bytes(payload[0:4], byteorder='big')
    
                    if int(payload[4]) == 7 and message_length < 1e6:
                        data_in_piece_length = len(payload) - 13
                        piece_index = int.from_bytes(payload[5:9], byteorder='big')
                        piece_offset = int.from_bytes(payload[9:13], byteorder='big')

                        pieces.add(piece_index)

                        found_stream = None

                        for (index, stream) in enumerate(tcp_streams):
                            if stream["src_ip"] == src_ip and stream["dst_ip"] == dst_ip and stream["src_port"] == src_port and stream["dst_port"] == dst_port:
                                found_stream = index

                        if found_stream is None:
                            tcp_streams.append({
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "src_port": src_port,
                                "dst_port": dst_port,
                                "remaining_bytes": message_length - 9 - data_in_piece_length
                            })
                        else:
                            tcp_streams[found_stream]["remaining_bytes"] = message_length - 9 - data_in_piece_length

                        files[info_hash]["size"] += data_in_piece_length

                    else:
                        found_stream = None

                        for (index, stream) in enumerate(tcp_streams):
                            if stream["src_ip"] == src_ip and stream["dst_ip"] == dst_ip and stream["src_port"] == src_port and stream["dst_port"] == dst_port:
                                found_stream = index

                        if found_stream is not None:
                            if len(payload) == 6 and payload == b'\0\0\0\0\0\0':
                                continue

                            if tcp_streams[found_stream]["remaining_bytes"] >= len(payload):
                                tcp_streams[found_stream]["remaining_bytes"] -= len(payload)
                                files[info_hash]["size"] += len(payload)

                            else:
                                new_payload = payload[tcp_streams[found_stream]["remaining_bytes"]:]

                                if len(new_payload) > 4 and int(new_payload[4]) == 7:
                                    message_length = int.from_bytes(new_payload[0:4], byteorder='big')
                                    piece_index = int.from_bytes(new_payload[5:9], byteorder='big')
                                    piece_offset = int.from_bytes(new_payload[9:13], byteorder='big')

                                    pieces.add(piece_index)

                                    data_in_piece_length = len(new_payload) - 13

                                    tcp_streams[found_stream]["remaining_bytes"] = message_length - 9 - data_in_piece_length

                                    files[info_hash]["size"] += data_in_piece_length
                                else:
                                    tcp_streams[found_stream]["remaining_bytes"] = 0

        files[info_hash]["pieces"].extend(sorted(pieces))
        files[info_hash]["contributes"].append({
            "ip": handshaked_ip,
            "port": handshaked_port,
            "pieces": sorted(pieces)
        })

    for handshaked_ip, handshaked_port, connection_id, info_hash in udp_handshaked_ips:
        file_bytes = 0
        remaining_bytes = 0
        pieces = set()

        for (packet_index, packet) in enumerate(packets):
            if UDP in packet and IP in packet and packet[IP].src == handshaked_ip and packet[UDP].sport == handshaked_port:
                payload = bytes(packet[UDP].payload)

                if len(payload) >= 20:
                    utp_header = payload[0:20]

                    this_connection_id = utp_header[2:4]

                    if this_connection_id == connection_id:
                        utp_payload = payload[20:]

                        if remaining_bytes < len(utp_payload):
                            utp_payload = utp_payload[remaining_bytes:]

                            if (len(utp_payload) >= 13 and utp_payload[4] == 7):
                                message_length = int.from_bytes(utp_payload[0:4], byteorder='big')
                                piece_index = int.from_bytes(utp_payload[5:9], byteorder='big')
                                piece_offset = int.from_bytes(utp_payload[9:13], byteorder='big')

                                pieces.add(piece_index)

                                data_in_piece_length = len(utp_payload) - 13

                                remaining_bytes = message_length - 9 - data_in_piece_length
                                file_bytes += message_length - 9
                        else:
                            remaining_bytes -= len(utp_payload)

        files[info_hash]["pieces"].extend(sorted(pieces))
        files[info_hash]["contributes"].append({
            "ip": handshaked_ip,
            "port": handshaked_port,
            "pieces": sorted(pieces)
        })
        files[info_hash]["size"] += file_bytes

    for file in files.keys():
        print("Infohash:", file)
        print("Size:", files[file]["size"], "B")
        print("Pieces:", len(list(set(files[file]["pieces"]))))
        print("Contributors:")
        
        for contributor in files[file]["contributes"]:
            if len(contributor["pieces"]) > 0:
                print("-", contributor["ip"] + ":" + str(contributor["port"]), len(contributor["pieces"]), "pieces")

elif operation == "rtable":
    client_ids = []
    transaction_ids = {}
    client_peers = {}
    owner_ip = None

    # Inspect all UDP packets
    for (index, packet) in enumerate(packets):
        if UDP in packet:
            bhtPayload = {}

            # If a UDP packet fails bdecoding we ignore it
            # because its either malformed or not BT-DHT at all
            try:
                bhtPayload, _ = bdecode(bytes(packet[UDP].payload))
            except:
                continue
            
            if owner_ip is None:
                owner_ip = packet[IP].src
            
            # handle BT-DHT requests
            if b'q' in bhtPayload and bhtPayload[b'q'] == b'get_peers' and packet[IP].src == owner_ip:
                client_id = toHex(bhtPayload[b'a'][b'id'])
                if not client_id in client_ids:
                    client_ids.append(client_id)
                    transaction_ids[client_id] = [toHex(bhtPayload[b't'])]
                    client_peers[client_id] = []

                transaction_ids[client_id].append(toHex(bhtPayload[b't']))
            
            # handle BT-DHT responses
            elif b'y' in bhtPayload and bhtPayload[b'y'] == b'r':
                trans_id = toHex(bhtPayload[b't'])
                for client_id in client_ids:
                    transactions = transaction_ids[client_id]

                    if trans_id in transactions:
                        if b'r' in bhtPayload and b'nodes' in bhtPayload[b'r']:
                            node_list = bhtPayload[b'r'][b'nodes']
                            sliced_ids = [node_list[i:i+26] for i in range(0, len(node_list), 26)]

                            nodes = list(map(
                                lambda x: Node(
                                    x[0:20],
                                    socket.inet_ntoa(x[20:24]),
                                    int.from_bytes(x[24:26], byteorder='big'),
                                    False,
                                    kademlia_distance(client_id, toHex(x[0:20]))
                                ),
                                sliced_ids
                            ))
                            
                            client_peers[client_id].extend(nodes)

    for single_client_peers in client_peers.keys():
        print("\nRouting table of", single_client_peers)

        # deduplicate entries and sort them by distance ascendingly
        client_peers[single_client_peers] = list(set(client_peers[single_client_peers]))
        client_peers[single_client_peers].sort(key=lambda node: node.distance)

        previousDistance = -1
        for node in client_peers[single_client_peers]:
            if (node.distance > previousDistance):
                previousDistance = node.distance
                print("\ndistance", node.distance)
            print(node)
        print()

else:
    eprint('Missing operation, use -init, -peers, -download or -rtable')
    sys.exit(1)
