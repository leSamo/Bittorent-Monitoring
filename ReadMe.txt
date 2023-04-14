BitTorrent network traffic detection
Samuel Olekšák
PDS 2022/23

Packet capture files:
installation - first startup of qBittorrent client after installation without downloading or seeding anything
startup - subsequent startup of qBittorrent client without downloading or seeding anything
dlseed - startup of qBittorent client, download of a single file, seeding, and download the same file from another machine

Detailed pcap file analysis: (> inbound, < outbound, = outbound and inbound in the sequence)
    installation
        < 1        DNS request for A record of dht.libtorrent.org
        < 2        DNS request for AAAA record of dht.libtorrent.org
        < 3        IGMPv3 join group 239.192.152.143 (local peer discovery address)
        < 4        MLDv2 listener report
        < 8        IGMPv3 join group 239.255.255.250 (SSDPaddress)
        > 9-10     DNS response for packets 1-2
        = 12-15    DNS request and response for A and AAAA for router.bittorent.com
        = 16-43    DNS request and response for A and AAAA for router.utorrent.com, geolite.maxmind.com, geolite.maxmind.com.kn.vutbr.cz, dht.transmissionbt.com, dht.aelitis.com, ec2-34-229-89-117.compute-1.amazonaws.com
        = 44-48    DHT Protocol (get_peers)
        < 49       Membership report 239.255.255.250
        = 50-82    DHT Protocol (get_peers)


The whole time SSDP to 239.255.255.250 with "M-SEARCH * HTTP/1.1" (searching for clients that are advertising themselves using BitTorrent peer discovery (BPD))



Analysis:
1. Place your packet capture files in .pcapng format into ./pcap/raw folder
2. Run extract.sh script which will convert raw .pcapng files from ./pcap/raw to .csv files in ./pcap/csv (this will also delete any previously existing csv files in ./pcap/csv)
3. Run analyze.py script to analyze csv files, run the script with -h switch to see available options
