#!/bin/bash

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fonction pour afficher les messages
print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Vérifier si le script est exécuté en tant que root
if [ "$EUID" -ne 0 ]; then 
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

# Vérifier et corriger les permissions
print_message "Vérification des permissions..."
ROOTKIT_DIR="$(pwd)/rootkit"
TMP_DIR="$ROOTKIT_DIR/.tmp_versions"

# Créer le répertoire temporaire s'il n'existe pas
mkdir -p "$TMP_DIR"

# Définir les permissions correctes
chmod -R 755 "$ROOTKIT_DIR"
chown -R root:root "$ROOTKIT_DIR"

# Nettoyer les fichiers temporaires avec sudo
print_message "Nettoyage des fichiers de compilation..."
rm -rf "$TMP_DIR"/* 2>/dev/null

# Vérifier l'espace disque
print_message "Vérification de l'espace disque..."
DISK_SPACE=$(df -h . | awk 'NR==2 {print $4}' | sed 's/G//')
if (( $(echo "$DISK_SPACE < 1" | bc -l) )); then
    print_error "Espace disque insuffisant. Au moins 1GB requis."
    exit 1
fi

# Vérifier la version du kernel
print_message "Vérification de la version du kernel..."
KERNEL_VERSION=$(uname -r)
if [ -z "$KERNEL_VERSION" ]; then
    print_error "Impossible de déterminer la version du kernel"
    exit 1
fi

# Vérifier les headers du kernel
print_message "Vérification des headers du kernel..."
if [ ! -d "/usr/src/linux-headers-$KERNEL_VERSION" ]; then
    print_error "Les headers du kernel ne sont pas installés"
    print_message "Installation des headers du kernel..."
    apt-get update
    apt-get install -y linux-headers-$KERNEL_VERSION
fi

# Compiler les modules
print_message "Compilation des modules kernel..."
cd "$ROOTKIT_DIR"
make clean
make

# Vérifier si la compilation a réussi
if [ ! -f "epirootkit.ko" ]; then
    print_error "La compilation a échoué"
    exit 1
fi

# Demander si l'utilisateur veut installer le module de manière persistante
read -p "Voulez-vous installer le module de manière persistante ? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Exécuter le script d'installation
    chmod +x install.sh
    ./install.sh
fi

print_message "Terminé" 