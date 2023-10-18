def CaesarCipher(str, key, encrypt):
    result = ""

    for i in range(len(str)):
        if (ord(str[i]) == 32):
            result += " "
        else:
            temp = ord(str[i]) - 65
            if (encrypt == "encrypt"):
                cipherIndex = (temp + key) % 26
            elif (encrypt == "decrypt"):
                cipherIndex = (temp - key) % 26
            result += chr(cipherIndex + 65)

    print(result)
    return result


for i in range(1, 26):
    CaesarCipher("AVKHF PZ H NVVK KHF", i, "decrypt")
