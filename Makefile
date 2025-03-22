obj-m = rootkit.o

PWD := $(shell pwd)
EXTRA_CFLAGS = -Wall -g

all:
	$(MAKE) ARCH=arm64 CROSS_COMPILE=$(CROSS) -C $(KDIR) M=$(PWD) modules
	$(CROSS)gcc $(EXTRA_CFLAGS) -o test test.c
	$(CROSS)gcc $(EXTRA_CFLAGS) -o child child.c 
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f test child
