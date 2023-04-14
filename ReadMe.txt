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
        = 16-43    DNS request and response for A and AAAA for router.utorrent.com, geolite.maxmind.com, geolite.maxmind.com.kn.vutbr.cz, dht.transmissionbt.com, dht.aelitis.com, ec2-34-229-89-117.compute-1.amazonaws.com (bootstrap nodes)
        = 44-48    DHT Protocol (get_peers)
        < 49       Membership report 239.255.255.250
        = 50-82    DHT Protocol (get_peers)


The whole time SSDP to 239.255.255.250 with "M-SEARCH * HTTP/1.1" (searching for clients that are advertising themselves using BitTorrent peer discovery (BPD))
Two NTP packets.

Script:
    Detection techniques:
        Without downloading/seeding:
            1. DNS to known bootstrap nodes (TODO: Find a comprehensive list of bootstrap nodes)
            2. Bootstrap node port (6881)
            3. Multicast join groups (239.192.152.143, 239.255.255.250)
            4. Bisect UDP packet content if it conforms to BT-DHT specification
            ?. SSDP (???)
        With downloading/seeding:
            1. LSD protocol with BT-SEARCH


    Info to print:
        - DNS queried bootstrap nodes/ports
        - multicast join groups
        - neighbor nodes


References:
    - https://blog.libtorrent.org/2016/09/dht-bootstrap-node/ - DHT bootstrap node
    - https://github.com/bittorrent/bootstrap-dht - Example of DHT bootstrap server 

Documentation:
    - Cons of using bootstrap nodes detection (list isn't comprehensive and can change, needs to be maintained, adversary could setup their own bootstrap nodes/proxy), port number can also be changed
    - Bdecoding
    - BT-DTH commands (get_peers, etc.)

Known bootstrap nodes: (usually port 6881)
    - router.utorrent.com (BitTorrent company)
    - router.bittorrent.com (BitTorrent company)
    - router.bitcomet.com (BitComet client)
    - dht.transmissionbt.com (Transmission client)
    - dht.aelitis.com
    ------------------------
    - dht.libtorrent.org (libtorrent-based clients)
    - dht.qbittorrent.org (qBittorrent client)
    - router.tixati.com (Tixati client)
    - dht.deluge-torrent.org (Deluge client)
    - dht.monova.org (general-purpose DHT node)
    - dht.net (general-purpose DHT node)
    - dht01.publicbt.com
    - dht02.publicbt.com
    - dht.rufus.sh
    - router.silotis.us
    - etc: https://gist.github.com/leSamo/146062ab60453309055b5caa709adddc

    Sources:
        - https://github.com/die-net/dhtproxy/blob/8bddafb4f9eef088de06cfb26d6b44dafca3997a/dht.go#L15
        - https://dev.deluge-torrent.org/browser/deluge/core/preferencesmanager.py?rev=415979e2f76658c4e325b7854f0a66206f0bc5c8#L320
        - https://git.deluge-torrent.org/deluge/tree/deluge/core/preferencesmanager.py#n264


Analysis:
1. Place your packet capture files in .pcapng format into ./pcap/raw folder
2. Run extract.sh script which will convert raw .pcapng files from ./pcap/raw to .csv files in ./pcap/csv (this will also delete any previously existing csv files in ./pcap/csv)
3. Run analyze.py script to analyze csv files, run the script with -h switch to see available options
