def bdecode(bencodedString):
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
