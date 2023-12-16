#!/bin/sh

qemu-system-x86_64 \
        -kernel bzImage \
        -append 'console=ttyS0 earlyprintk=serial root=/dev/sda panic=0 kaslr' \
        -drive file="./root.img",if=ide \
        -m 1G \
        -cpu kvm64,+smap,+smep -smp cores=2 -nographic \
        -net nic,model=virtio-net-pci \
        -monitor /dev/null \
        -snapshot

