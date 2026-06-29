#!/bin/sh

qemu-system-x86_64 \
	-kernel ./bzImage \
	-cpu qemu64,+smap,+smep \
	-smp 1 \
	-m 256M \
	-initrd ./initramfs.cpio.gz \
	-append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 nokaslr panic=-1 pti=on" \
	-no-reboot \
	-nographic \
	-monitor /dev/null \
	-drive format=raw,file="$1",if=virtio \
    -s \
