# Configuration
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
MODULE_NAME := epirootkit

# Flags de compilation
EXTRA_CFLAGS += -Wall
EXTRA_CFLAGS += -Wno-pointer-to-int-cast
EXTRA_CFLAGS += -Wno-int-to-pointer-cast
EXTRA_CFLAGS += -Wno-unused-variable
EXTRA_CFLAGS += -Wno-unused-function
EXTRA_CFLAGS += -Wno-implicit-function-declaration
EXTRA_CFLAGS += -fno-strict-aliasing

# Objets à compiler
obj-m := $(MODULE_NAME).o

# Règles principales
all:
	@echo "Compilation du module kernel..."
	@$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	@echo "Nettoyage des fichiers de compilation..."
	@rm -f *.o *.ko *.mod.c *.mod.o *.symvers *.order
	@rm -f .*.cmd
	@rm -rf .tmp_versions

# Installation
install: all
	@echo "Installation du module..."
	@if lsmod | grep -q "$(MODULE_NAME)"; then \
		echo "Déchargement du module existant..."; \
		rmmod $(MODULE_NAME); \
	fi
	@insmod $(MODULE_NAME).ko

uninstall:
	@echo "Désinstallation du module..."
	@if lsmod | grep -q "$(MODULE_NAME)"; then \
		rmmod $(MODULE_NAME); \
	fi

.PHONY: all clean install uninstall
