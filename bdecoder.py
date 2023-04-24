"""
    Monitoring of BitTorrent Traffic in LAN
    PDS project 2022/23
    Samuel Olekšák (xoleks00)
"""

# Decoder of bencoding defined by BEP-0005 (https://www.bittorrent.org/beps/bep_0005.html)
# Returns a tuple where first item is the parsed structure and second is
# either empty if the input string was parsed fully, or the unparseable
# tail of the string
def bdecode(bencodedString):
        if bencodedString[0] == ord("i"):
            slicedInteger = bencodedString[1:].split(b"e")[0]
            return (int(slicedInteger), bencodedString[1 + len(slicedInteger) + 1:])
        elif bencodedString[0] in range(ord("0"), ord("9") + 1):
            lengthUncasted = bencodedString.split(b":")[0]
            return (
                b"".join(bencodedString.split(b":")[1:])[:int(lengthUncasted)],
                bencodedString[len(lengthUncasted) + int(lengthUncasted) + 1:]
            )
        elif bencodedString[0] == ord("l"):
            rest = bencodedString[1:]
            listSoFar = []
            while rest[0] != ord("e"):
                (item, rest) = bdecode(rest)
                listSoFar.append(item)
            return (listSoFar, rest[1:])
        elif bencodedString[0] == ord("d"):
            rest = bencodedString[1:]
            dictSoFar = {}
            while rest[0] != ord("e"):
                (key, rest) = bdecode(rest)
                (value, rest) = bdecode(rest)
                dictSoFar[key] = value
            return (dictSoFar, rest[1:])
        else:
            raise Exception
