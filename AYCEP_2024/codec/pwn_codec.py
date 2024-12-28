#!/bin/python3

from pwn import *
import codecs

proc = process("./codec")

proc.recvuntil(b">> ")
proc.sendline(b"Yes")

proc.recvuntil(b"to me\n")
answer = proc.recvline().strip(b"\n")
proc.sendline(answer)

proc.recvuntil(b"uppercase\n")
answer = proc.recvline().strip(b"\n").decode("utf-8").upper()
answer = answer.encode("utf-8")
proc.recvuntil(b">> ")
proc.sendline(answer)

proc.recvuntil(b"rot13\n")
answer = proc.recvline().strip(b"\n").decode("utf-8")
answer = codecs.encode(answer, "rot_13")
proc.sendline(answer)

proc.recvuntil(b"?\n")
answer = b"If ya wanna win, ya gotta want it!"
proc.sendline(answer)

proc.interactive()
proc.close()
