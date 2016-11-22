obj-m += antivirus.o 
antivirus-objs := kern_helper.o kdriver.o

all:
	make   -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm popup
