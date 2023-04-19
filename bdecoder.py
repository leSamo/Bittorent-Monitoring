def bdecode(bencodedString):
        #print("DECODING", bencodedString)
    #try:
        if bencodedString[0] == ord("i"):
            slicedInteger = bencodedString[1:].split(b"e")[0]
            return (int(slicedInteger), bencodedString[1 + len(slicedInteger) + 1:])
        elif bencodedString[0] in range(ord("0"), ord("9") + 1):
            lengthUncasted = bencodedString.split(b":")[0]
            return (b"".join(bencodedString.split(b":")[1:])[:int(lengthUncasted)], bencodedString[len(lengthUncasted) + int(lengthUncasted) + 1:])
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
            #print("Error: First char is", chr(bencodedString[0]), "(", bencodedString[0], ")")
            raise Exception
    #except:
        #print("Bdecoding error")

"""
print(bdecode(b"i-42e_REST"))
print(bdecode(b"5:hello_REST"))
print(bdecode(b"le"))
print(bdecode(b"l4:spami42ee_REST"))
print(bdecode(b"l4:spaml4:spami42eee"))
print(bdecode(b"de"))
print(bdecode(b"d3:bar4:spam3:fooi42ee"))
print(bdecode(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"))
print(bdecode(b"d1:c1:d1:dde4:dictd1:a1:b3:inti123e5:list1le5:list2li123e4:ahojdeli1ei2e3:caued1:5i6eeee3:inti-42e1:llee"))
#print(bdecode(b"d10:created by18:qBittorrent v4.5.013:creation datei1676736717e4:infod6:lengthi16e4:name7:PDS.txt12:piece lengthi16384e6:pieces20:�>���ʪ�x�amt���'\�Yee"))
"""

print(bdecode(b"d6:lengthi16e4:name7:PDS.txt12:piece lengthi16384ee"))