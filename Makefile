KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m += kvmmtest.o

#EXTRA_CFLAGS = -DDEBUG -g
MAKE_ARGS =
ifdef ARCH
MAKE_ARGS += ARCH=$(ARCH)
endif
ifdef CROSS_COMPILE
MAKE_ARGS += CROSS_COMPILE=$(CROSS_COMPILE)
endif


all:
	make -C $(KDIR) $(MAKE_ARGS) M=$(PWD) modules
clean:
	make -C $(KDIR) $(MAKE_ARGS) M=$(PWD) clean 
