#!/bin/sh
qemu-system-x86_64 \
    -kernel ./bzImage \
    -cpu qemu64,+smep,+smap \
    -m 2G \
    -smp 2 \
    -initrd initramfs.cpio.gz \
    -append "console=ttyS0 quiet loglevel=3 kaslr kpti=1" \
    -monitor /dev/null \
    -nographic \
    -no-reboot \
