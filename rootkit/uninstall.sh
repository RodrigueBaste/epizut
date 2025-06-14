#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_message() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

print_message "Arrêt du service systemd..."
if systemctl is-enabled --quiet epirootkit.service; then
    systemctl stop epirootkit.service
    systemctl disable epirootkit.service
    rm -f /etc/systemd/system/epirootkit.service
    systemctl daemon-reexec
    systemctl daemon-reload
else
    print_warning "Le service epirootkit n'est pas actif ou déjà supprimé."
fi

print_message "Suppression du module du noyau..."
if lsmod | grep -q "epirootkit"; then
    rmmod epirootkit || true
else
    print_warning "Le module epirootkit n'était pas chargé."
fi

print_message "Nettoyage des fichiers système..."
rm -f /lib/modules/$(uname -r)/extra/epirootkit.ko
depmod -a

print_message "Suppression terminée. Reboot recommandé pour finaliser le nettoyage."
