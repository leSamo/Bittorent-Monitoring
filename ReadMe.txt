BitTorrent network traffic detection
Samuel Olekšák (xoleks00)
PDS 2022/23

Requirements:
Python 3.6.7
Scapy 2.5.0

Zip file contents:
|- pcap/
  |- q-download-tcp.pcapng
  |- q-download-udp.pcapng
  |- q-installation.pcapng
  |- q-startup.pcapng
|- torrent/
  |- images.torrent
  |- mnist.torrent
|- bdecoder.py
|- bt-monitor
|- bt-monitor.py
|- documentation.pdf
|- node.py
|- Readme.txt
|- requirements.txt

Analysis tool:
bt-monitor - script for monitoring of BitTorrent traffic in LAN

Usage:
python3 bt-monitor -pcap <path_to_pcap_file> [-init|-peers|-download|-rtable]
  -init: returns a list of detected bootstrap nodes
  -peers: returns a list of detected neighbors
  -download: returns file info_hash, size, chunks, contributes
  -rtable: returns the routing table of the client

Packet preprocessing:
There is no need for any packet preprocessing, the script expects packets
in pcap format.

Implemented parts of the assignment:
The analysis tool has all of the functionality described in the assignment.
Their functionality was validated using the included packet capture files.
Routing table optional extension is implemented as well.
