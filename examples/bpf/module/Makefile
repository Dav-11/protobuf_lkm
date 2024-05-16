KDIR ?= /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)
EXTRA_CFLAGS += -DDEBUG
obj-m += protobuf_lkm.o

protobuf_lkm-y 	:= \
	main.o \
	../../../common/protobuf_lkm.o

build:

	@echo
	@echo '--- Building : KDIR=${KDIR} ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} EXTRA_CFLAGS=${EXTRA_CFLAGS} ---'
	@echo

	# build
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	@echo
	@echo "--- installing ---"
	@echo " [First, invoke the 'make' ]"
	make
	@echo
	@echo " [Now for the 'sudo make install' ]"
	sudo make -C $(KDIR) M=$(PWD) modules_install
	sudo depmod

clean:
	@echo
	@echo "--- cleaning ---"
	@echo
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod $(PWD)/protobuf_lkm.ko

unload:
	sudo rmmod protobuf_lkm
