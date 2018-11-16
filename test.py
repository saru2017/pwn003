import codecs

s = b"/bin/sh"

#print(binascii.unhexlify("12345"))
#print(codecs.decode('ha', 'hex'))
#print(str.decode("hex"))
#print(hex(s))

#print("%x" % s)

for val in s:
    print("0x%02x " % (val), end="")

print("")

