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

# Définitions nécessaires
EXTRA_CFLAGS += -DCONFIG_X86_32
EXTRA_CFLAGS += -DCONFIG_PARAVIRT
EXTRA_CFLAGS += -DCONFIG_PARAVIRT_SPINLOCKS
EXTRA_CFLAGS += -DCONFIG_KVM_GUEST
EXTRA_CFLAGS += -DCONFIG_RETPOLINE
EXTRA_CFLAGS += -DCONFIG_SPARSEMEM
EXTRA_CFLAGS += -DCONFIG_SPARSEMEM_VMEMMAP
EXTRA_CFLAGS += -DCONFIG_PAGE_OFFSET=0xC0000000
EXTRA_CFLAGS += -DPAGE_SHIFT=12
EXTRA_CFLAGS += -DPMD_SHIFT=21
EXTRA_CFLAGS += -DPUD_SHIFT=30
EXTRA_CFLAGS += -DPTRS_PER_PMD=512
EXTRA_CFLAGS += -DPTRS_PER_PUD=4
EXTRA_CFLAGS += -D__PHYSICAL_MASK=0xFFFFFFFF
EXTRA_CFLAGS += -D__VIRTUAL_MASK=0xFFFFFFFF

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
