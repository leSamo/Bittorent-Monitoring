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

def to_hex(rawBytes):
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

# Bittorrent command for 
BT_PIECE = 7

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

# ------------------
# DNS PACKET PARSING
# ------------------

# Accepts list of raw packets
# Inspects all DNS packets and returns a list of IPv4 and IPv6 addresses which
# were received inside DNS responses
def get_dns_received_ips(packets):
    dns_received_addresses = set()
    
    for packet in packets:
        # Check if packet is a DNS response and extract IP address
        if packet.haslayer(DNSRR):
            dns_layer = packet.getlayer(DNSRR)

            for i in range(packet[DNS].ancount):
                 # Check if DNS response contains A (IPv4) or AAAA (IPv6) record
                if dns_layer[i].type == 1 or dns_layer[i].type == 28:
                    ip = dns_layer[i].rdata
                    dns_received_addresses.add(ip)

    return dns_received_addresses

# ------------------
# DHT PACKET PARSING
# ------------------

# Expects list of raw packets
# Returns a tuple - list of detected nodes in Node dataclass and a dictionary
# of transaction ids along with the number of packets that used that id
def detect_received_nodes(packets):
    detected_nodes = set()
    transaction_ids = {}
    dns_received_addresses = get_dns_received_ips(packets)

    # Inspect all UDP packets
    for packet in packets:
        if UDP in packet:
            bht_payload = {}

            # If a UDP packet fails bdecoding we ignore it
            # because its either malformed or not BT-DHT at all
            try:
                bht_payload, _ = bdecode(bytes(packet[UDP].payload))
            except:
                continue
            
            # Extract and save transaction ids
            if b't' in bht_payload:
                if to_hex(bht_payload[b't']) in transaction_ids:
                    transaction_ids[to_hex(bht_payload[b't'])] += 1
                else:
                    transaction_ids[to_hex(bht_payload[b't'])] = 1

            # Handle BT-DHT requests
            if (b'a' in bht_payload and b'id' in bht_payload[b'a'] and
                b'q' in bht_payload and bht_payload[b'q'] == b'get_peers'):
                dst_ip = packet[IP].dst
                dst_port = packet[UDP].dport

                # If bencoding contains { bs: 1 } or IP address was received by DNS,
                # consider it bootstrap
                # Save destination IP address and port without the ID for now
                # ID will be possibly filled out later when response in received
                if ((b'bs' in bht_payload[b'a'] and bht_payload[b'a'][b'bs'] == 1)
                    or dst_ip in dns_received_addresses):
                    detected_nodes.add(Node("Unknown", dst_ip, dst_port, True, -1))
                else:
                    detected_nodes.add(Node("Unknown", dst_ip, dst_port, False, -1))

            # Handle BT-DHT responses
            elif (b'r' in bht_payload and b'id' in bht_payload[b'r']):
                src_ip = packet[IP].src
                src_port = packet[UDP].sport
                id = bht_payload[b'r'][b'id']

                # Match the received ID to source IP and port in our database
                for node in detected_nodes:
                    if node.ip_address == src_ip and node.port == src_port:
                        node.id = id
                        break
                
                # Save all of the received nodes
                # Nodes are stored packed in 26 bytes and need to be sliced by bits
                if b'nodes' in bht_payload[b'r']:
                    node_list = bht_payload[b'r'][b'nodes']
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

                    # Match ids to nodes which have IP address + port already saved
                    for node in nodes:
                        added = False

                        for detected_node in detected_nodes:
                            if (node.ip_address == detected_node.ip_address
                                and node.port == detected_node.port):
                                detected_node.id = node.id
                                added = True
                                break
                        
                        if not added:
                            detected_nodes.add(node)

    return (detected_nodes, transaction_ids)

# Accepts two ids in hex format and returns in how many
# bits their prefixes match
def kademlia_distance(hex_id_1, hex_id_2):
    # Convert hex to binary, remove 0b prefix and pad it to 160 bits
    id_1 = bin(int(hex_id_1, 16))[2:].zfill(160)
    id_2 = bin(int(hex_id_2, 16))[2:].zfill(160)
    
    prefix_bit_count = 0

    # Count how many bits from the start match up
    for i in range(len(id_1)):
        if id_1[i] != id_2[i]:
            break
        else:
            prefix_bit_count += 1
    
    return prefix_bit_count

# --------------------
# CLIENT ID RESOLUTION
# --------------------

# Goes throught all of the packets and finds the IP address which is sender
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
    received_nodes, _ = detect_received_nodes(packets)

    # Get all nodes and filter out those, which are not bootstrap
    bootstrap_nodes = list(filter(lambda node: node.is_bootstrap, received_nodes))

    print("Detected boostrap nodes:\n")
    print(f"ID                                       Port  IP address")

    for node in bootstrap_nodes:
        print(node)

elif operation == "peers":
    received_nodes, transaction_ids = detect_received_nodes(packets)

    print("Detected neighbor nodes:\n")
    print(f"ID                                       Port  IP address")
    
    for node in received_nodes:
        print(node)

    # Only count connections which have at least 2 packets
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

        # Handle UDP handshakes
        if UDP in packet:

            # UDP Bittorrent handshake is 88 bytes long (20 uTP + 68 BT)
            if len(payload) >= 88 and payload[20] == 19 and payload[21:40] == b'BitTorrent protocol':
                dst = packet[IP].dst
                src = packet[IP].src
                connection_id = payload[2:4]
                info_hash = payload[48:68]

                # Only include incoming handshakes (we don't care about seeding)
                if dst == client_ip:
                    udp_handshaked_ips.add((src, sport, connection_id, to_hex(info_hash)))

        # Handle TCP handshakes
        if TCP in packet:
            if len(payload) > 19:
                protocol_name_length = int(payload[0])

                if protocol_name_length == 19 and payload[1:20] == b'BitTorrent protocol':
                    reserved = payload[20:28]
                    info_hash = payload[28:48]
                    peer_id = payload[48:68]

                    files[to_hex(info_hash)] = {
                        "size": 0,
                        "streams": 0,
                        "pieces": [],
                        "contributes": [{
                            "ip": packet[IP].dst,
                            "port": dport,
                            "pieces": []
                        }]
                    }

                    # Only include outgoing handshakes
                    if (packet[IP].dst != client_ip):
                        tcp_handshaked_ips.add((packet[IP].dst, packet[TCP].dport, to_hex(info_hash)))

    # Handle incoming TCP Bittorrent packets with piece command and their continuation
    for handshaked_ip, handshaked_port, info_hash in tcp_handshaked_ips:
        tcp_streams = []
        pieces = set()

        for (packet_index, packet) in enumerate(packets):
            if (IP in packet and
                packet[IP].src == handshaked_ip and
                TCP in packet and
                packet[TCP].sport == handshaked_port):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                payload = bytes(packet[TCP].payload)

                if len(payload) > 4:
                    message_length = int.from_bytes(payload[0:4], byteorder='big')

                    # Handle piece start
                    # Safety check, it does not make sense to have piece larger than 1e6 bytes
                    if int(payload[4]) == BT_PIECE and message_length < 1e6:
                        data_in_piece_length = len(payload) - 13
                        piece_index = int.from_bytes(payload[5:9], byteorder='big')
                        piece_offset = int.from_bytes(payload[9:13], byteorder='big')

                        pieces.add(piece_index)

                        found_stream = None

                        # Try to match packet to existing stream
                        for (index, stream) in enumerate(tcp_streams):
                            if (stream["src_ip"] == src_ip and
                                stream["dst_ip"] == dst_ip and
                                stream["src_port"] == src_port and
                                stream["dst_port"] == dst_port):
                                found_stream = index

                        # If stream is not found, create a new one
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

                    # Handle piece continuation
                    else:
                        found_stream = None

                        # Try to match continuation packet to existing stream
                        for (index, stream) in enumerate(tcp_streams):
                            if (stream["src_ip"] == src_ip and
                                stream["dst_ip"] == dst_ip and
                                stream["src_port"] == src_port and
                                stream["dst_port"] == dst_port):
                                found_stream = index

                        # Ignore TCP packets which are not continuation of piece command packet
                        if found_stream is not None:
                            # Ignore empty TCP packets with padding only
                            if len(payload) == 6 and payload == b'\0\0\0\0\0\0':
                                continue

                            # Record bytes of continuation packets
                            if tcp_streams[found_stream]["remaining_bytes"] >= len(payload):
                                tcp_streams[found_stream]["remaining_bytes"] -= len(payload)
                                files[info_hash]["size"] += len(payload)

                            # Handle packets which have continuation data and a new Bittorrent header
                            else:
                                new_payload = payload[tcp_streams[found_stream]["remaining_bytes"]:]

                                # Check if continuation header has piece command
                                if len(new_payload) > 4 and int(new_payload[4]) == BT_PIECE:
                                    message_length = int.from_bytes(new_payload[0:4], byteorder='big')
                                    piece_index = int.from_bytes(new_payload[5:9], byteorder='big')
                                    piece_offset = int.from_bytes(new_payload[9:13], byteorder='big')

                                    pieces.add(piece_index)

                                    data_in_piece_length = len(new_payload) - 13

                                    tcp_streams[found_stream]["remaining_bytes"] = message_length - 9 - data_in_piece_length

                                    files[info_hash]["size"] += data_in_piece_length
                                # Failsafe is something goes wrong so that byte count will only be off by a bit
                                else:
                                    tcp_streams[found_stream]["remaining_bytes"] = 0

        files[info_hash]["pieces"].extend(sorted(pieces))
        files[info_hash]["contributes"].append({
            "ip": handshaked_ip,
            "port": handshaked_port,
            "pieces": sorted(pieces)
        })

    # Handle UDP streams
    for handshaked_ip, handshaked_port, connection_id, info_hash in udp_handshaked_ips:
        file_bytes = 0
        remaining_bytes = 0
        pieces = set()

        for (packet_index, packet) in enumerate(packets):
            if UDP in packet and IP in packet and packet[IP].src == handshaked_ip and packet[UDP].sport == handshaked_port:
                payload = bytes(packet[UDP].payload)

                # uTP header has 20 bytes
                if len(payload) >= 20:
                    utp_header = payload[0:20]

                    this_connection_id = utp_header[2:4]

                    # Match this stream to a known connection id
                    if this_connection_id == connection_id:
                        utp_payload = payload[20:]

                        # Bittorrent header is either at the start or this is a continuation packet
                        # and header might be inside the payload
                        if remaining_bytes < len(utp_payload):
                            utp_payload = utp_payload[remaining_bytes:]

                            # Check if continuation header has piece command
                            if (len(utp_payload) >= 13 and utp_payload[4] == BT_PIECE):
                                message_length = int.from_bytes(utp_payload[0:4], byteorder='big')
                                piece_index = int.from_bytes(utp_payload[5:9], byteorder='big')
                                piece_offset = int.from_bytes(utp_payload[9:13], byteorder='big')

                                pieces.add(piece_index)

                                data_in_piece_length = len(utp_payload) - 13

                                remaining_bytes = message_length - 9 - data_in_piece_length
                                file_bytes += message_length - 9
                        # Only continuation data without new Bittorrent header
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
            bht_payload = {}

            # If a UDP packet fails bdecoding we ignore it
            # because its either malformed or not BT-DHT at all
            try:
                bht_payload, _ = bdecode(bytes(packet[UDP].payload))
            except:
                continue
            
            if owner_ip is None:
                owner_ip = packet[IP].src
            
            # Handle BT-DHT requests
            if b'q' in bht_payload and bht_payload[b'q'] == b'get_peers' and packet[IP].src == owner_ip:
                client_id = to_hex(bht_payload[b'a'][b'id'])

                if not client_id in client_ids:
                    client_ids.append(client_id)
                    transaction_ids[client_id] = [to_hex(bht_payload[b't'])]
                    client_peers[client_id] = []

                transaction_ids[client_id].append(to_hex(bht_payload[b't']))
            
            # Handle BT-DHT responses
            elif b'y' in bht_payload and bht_payload[b'y'] == b'r':
                transaction_id = to_hex(bht_payload[b't'])
                for client_id in client_ids:
                    transactions = transaction_ids[client_id]

                    # Only record ids from connections which client initiated
                    if transaction_id in transactions:
                        if b'r' in bht_payload and b'nodes' in bht_payload[b'r']:
                            node_list = bht_payload[b'r'][b'nodes']
                            sliced_ids = [node_list[i:i+26] for i in range(0, len(node_list), 26)]

                            nodes = list(map(
                                lambda x: Node(
                                    x[0:20],
                                    socket.inet_ntoa(x[20:24]),
                                    int.from_bytes(x[24:26], byteorder='big'),
                                    False,
                                    kademlia_distance(client_id, to_hex(x[0:20]))
                                ),
                                sliced_ids
                            ))
                            
                            client_peers[client_id].extend(nodes)

    for single_client_peers in client_peers.keys():
        print("\nRouting table of", single_client_peers)

        # Deduplicate entries and sort them by distance ascendingly
        client_peers[single_client_peers] = list(set(client_peers[single_client_peers]))
        client_peers[single_client_peers].sort(key=lambda node: node.distance)

        previous_distance = -1
        for node in client_peers[single_client_peers]:
            if (node.distance > previous_distance):
                previous_distance = node.distance
                print("\ndistance", node.distance)
            print(node)
        print()

else:
    eprint('Missing operation, use -init, -peers, -download or -rtable')
    sys.exit(1)
