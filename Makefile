KERN_COMP = clang
KERN_ARGS = -I /usr/include/x86_64-linux-gnu -O2 -target bpf
KERN_TARGET = xdp.elf
KERN_DIR = ./kernel_program/
KERN_PROG = xdp.c


all: kernel-only

kernel-only:
	${KERN_COMP} ${KERN_ARGS} -c ${KERN_DIR}${KERN_PROG} -o ${KERN_DIR}${KERN_TARGET}