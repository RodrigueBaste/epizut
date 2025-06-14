# Configuration
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
MODULE_NAME := epirootkit

# Flags de compilation
EXTRA_CFLAGS += -Wall -Wextra -std=gnu99
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -Wno-unused-parameter

# Objets à compiler
obj-m += $(MODULE_NAME).o

# Règles principales
all:
	@echo "Compilation du module kernel..."
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	@echo "Nettoyage des fichiers de compilation..."
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	@rm -f *.o *.ko *.mod.c *.mod.o *.symvers *.order
	@rm -f .*.cmd
	@rm -rf .tmp_versions

.PHONY: all clean
