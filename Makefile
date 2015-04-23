ifneq (${KERNELRELEASE},)
	obj-m := thedoor.o
else
	KERNEL_SOURCE := $(shell pwd)/linux
	PWD := $(shell pwd)
default:
	$(MAKE) -C ${KERNEL_SOURCE} SUBDIRS=${PWD} modules

clean:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} clean
endif
