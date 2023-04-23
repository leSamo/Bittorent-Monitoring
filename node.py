"""
    Monitoring of BitTorrent Traffic in LAN
    PDS project 2022/23
    Samuel Olekšák (xoleks00)
"""

import binascii
from dataclasses import dataclass

@dataclass
class Node:
    id: bytes
    ip_address: bytes
    port: bytes
    is_bootstrap: bool
    distance: int

    def __repr__(self):
        id = "Unknown (did not respond)" if self.id == "Unknown" else binascii.hexlify(self.id).decode()
        return f"{id.ljust(40)} {str(self.port).ljust(5)} {self.ip_address}"

    def __hash__(self):
        return hash((self.id, self.ip_address, self.port, self.is_bootstrap, self.distance))
