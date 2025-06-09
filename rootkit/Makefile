# Configuration
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
MODULE_NAME := epirootkit
TEST_MODULE_NAME := test_epirootkit

# Flags de compilation
EXTRA_CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-unused-variable
EXTRA_CFLAGS += -DDEBUG

# Objets à compiler
obj-m := $(MODULE_NAME).o $(TEST_MODULE_NAME).o

# Dépendances
$(MODULE_NAME)-objs := epirootkit.o
$(TEST_MODULE_NAME)-objs := test_epirootkit.o

# Règles principales
all: check_kernel check_headers
	@echo "Compilation des modules kernel..."
	@make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	@echo "Nettoyage des fichiers de compilation..."
	@make -C $(KERNEL_DIR) M=$(PWD) clean
	@rm -f *.o *.ko *.mod.c *.mod.o *.symvers *.order
	@rm -f .*.cmd
	@rm -rf .tmp_versions

# Vérifications
check_kernel:
	@echo "Vérification de la version du kernel..."
	@if [ "$(shell uname -r | cut -d. -f1,2)" \< "4.0" ]; then \
		echo "Erreur: Le kernel doit être en version 4.0.0 ou supérieure"; \
		exit 1; \
	fi

check_headers:
	@echo "Vérification des headers du kernel..."
	@if [ ! -d "$(KERNEL_DIR)" ]; then \
		echo "Erreur: Les headers du kernel ne sont pas installés"; \
		echo "Exécutez: sudo apt-get install linux-headers-$(shell uname -r)"; \
		exit 1; \
	fi

# Tests
test: all
	@echo "Test du module..."
	@if lsmod | grep -q "$(TEST_MODULE_NAME)"; then \
		echo "Déchargement du module de test existant..."; \
		rmmod $(TEST_MODULE_NAME); \
	fi
	@insmod $(TEST_MODULE_NAME).ko
	@rmmod $(TEST_MODULE_NAME)

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

# Aide
help:
	@echo "Commandes disponibles:"
	@echo "  make        - Compile les modules kernel"
	@echo "  make clean  - Nettoie les fichiers de compilation"
	@echo "  make test   - Compile et teste le module de test"
	@echo "  make install   - Compile et installe le module"
	@echo "  make uninstall - Désinstalle le module"
	@echo "  make help   - Affiche cette aide"

.PHONY: all clean test install uninstall help check_kernel check_headers
