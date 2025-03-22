obj-m = rootkit.o

PWD := $(shell pwd)
EXTRA_CFLAGS = -Wall -g

all:
	$(MAKE) ARCH=arm64 CROSS_COMPILE=$(CROSS) -C $(KDIR) M=$(PWD) modules
	$(CROSS)gcc $(EXTRA_CFLAGS) -o rootkit_test rootkit_test.c
	$(CROSS)gcc $(EXTRA_CFLAGS) -o rootkit_test_child rootkit_test_child.c 
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f rootkit_test rootkit_test_child
