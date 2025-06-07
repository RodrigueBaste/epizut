# Guide de Configuration des VMs pour EpiRootkit

Ce guide détaille la configuration des deux machines virtuelles nécessaires pour le projet EpiRootkit : une VM victime et une VM attaquant.

## Table des matières
1. [Configuration des VMs](#1-configuration-des-vms)
2. [Installation de la VM Victime](#2-installation-de-la-vm-victime)
3. [Installation de la VM Attaquant](#3-installation-de-la-vm-attaquant)
4. [Configuration réseau](#4-configuration-réseau)
5. [Configuration post-installation](#5-configuration-post-installation)
6. [Vérification de la configuration](#6-vérification-de-la-configuration)
7. [Sécurité et bonnes pratiques](#7-sécurité-et-bonnes-pratiques)

## 1. Configuration des VMs

### VM Victime
- **Système d'exploitation** : Ubuntu Desktop 22.04.3 LTS
- **Version du kernel** : 
  - Minimum : 4.0.0
  - Recommandée : 5.15.0
- **Configuration minimale** :
  - 2 CPU
  - 2 GB RAM
  - 20 GB disque
  - Interface réseau : NAT

### VM Attaquant
- **Système d'exploitation** : Ubuntu Desktop 22.04.3 LTS
- **Configuration minimale** :
  - 1 CPU
  - 1 GB RAM
  - 20 GB disque
  - Interface réseau : NAT

## 2. Installation de la VM Victime

1. Télécharger Ubuntu Desktop 22.04.3 LTS :
```bash
wget https://old-releases.ubuntu.com/releases/22.04.3/ubuntu-22.04.3-desktop-amd64.iso
```

2. Créer la VM avec VirtualBox :
```bash
VBoxManage createvm --name "EpiRootkit-Victim" --ostype Ubuntu_64 --register
VBoxManage modifyvm "EpiRootkit-Victim" --memory 2048 --cpus 2
VBoxManage createhd --filename "EpiRootkit-Victim.vdi" --size 20480
VBoxManage storagectl "EpiRootkit-Victim" --name "SATA Controller" --add sata --controller IntelAhci
VBoxManage storageattach "EpiRootkit-Victim" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "EpiRootkit-Victim.vdi"
VBoxManage storageattach "EpiRootkit-Victim" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "./ubuntu-22.04.3-desktop-amd64.iso"
```

3. Lancer la VM et suivre l'assistant d'installation graphique :
   - Choisir "Install Ubuntu"
   - Sélectionner la langue et la disposition du clavier
   - Choisir "Normal installation" avec "Download updates while installing"
   - Sélectionner "Erase disk and install Ubuntu"
   - Créer un utilisateur avec un mot de passe fort
   - Attendre la fin de l'installation
   - Redémarrer la VM

4. Après l'installation, vérifier et configurer la version du kernel :
```bash
# Vérifier la version actuelle du kernel
uname -r

# Si la version n'est pas 5.15.0, installer le kernel spécifique
sudo apt update
sudo add-apt-repository universe
sudo add-apt-repository multiverse
sudo apt update
sudo apt install --install-recommends linux-generic-hwe-22.04

# Mettre à jour GRUB
sudo update-grub

# Redémarrer la VM
sudo reboot

# Après le redémarrage, vérifier la version du kernel
uname -r  # Doit afficher 5.15.0-XX-generic
```

5. Désactiver les mises à jour automatiques pour éviter les mises à jour non désirées du kernel :
```bash
# Désactiver les mises à jour automatiques
sudo systemctl disable apt-daily.service
sudo systemctl disable apt-daily.timer
sudo systemctl disable apt-daily-upgrade.service
sudo systemctl disable apt-daily-upgrade.timer

# Vérifier que les services sont bien désactivés
systemctl status apt-daily.service
systemctl status apt-daily.timer
systemctl status apt-daily-upgrade.service
systemctl status apt-daily-upgrade.timer
```

6. Configurer le système pour maintenir la version du kernel :
```bash
# Empêcher la mise à jour du kernel
sudo apt-mark hold linux-image-generic linux-headers-generic

# Vérifier que le kernel est bien en "hold"
apt-mark showhold
```

7. Vérifier que tout est correctement configuré :
```bash
# Vérifier la version du kernel
uname -r

# Vérifier les modules kernel installés
ls /lib/modules/

# Vérifier que les headers sont présents
ls /usr/src/linux-headers-5.15.0-*
```

Ces étapes garantissent que :
- Ubuntu 22.04 LTS est installé
- Le kernel 5.15.0 est installé et configuré
- Les mises à jour automatiques sont désactivées
- Le kernel ne sera pas mis à jour automatiquement
- Tous les composants nécessaires pour le développement du rootkit sont présents

## 3. Installation de la VM Attaquant

1. Créer la VM avec VirtualBox :
```bash
VBoxManage createvm --name "EpiRootkit-Attacker" --ostype Ubuntu_64 --register
VBoxManage modifyvm "EpiRootkit-Attacker" --cpus 2 --memory 2048 --vram 64
VBoxManage createhd --filename "EpiRootkit-Attacker.vdi" --size 20480
VBoxManage storagectl "EpiRootkit-Attacker" --name "SATA Controller" --add sata --controller IntelAhci
VBoxManage storageattach "EpiRootkit-Attacker" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "EpiRootkit-Attacker.vdi"
VBoxManage storageattach "EpiRootkit-Attacker" --storagectl "SATA Controller" --port 1 --device 0 --type dvddrive --medium "/Users/rodriguebaste/Downloads/ubuntu-22.04.3-desktop-amd64.iso"
```

2. Lancer la VM et suivre l'assistant d'installation graphique :
   - Choisir "Install Ubuntu"
   - Sélectionner la langue et la disposition du clavier
   - Choisir "Normal installation" avec "Download updates while installing"
   - Sélectionner "Erase disk and install Ubuntu"
   - Créer un utilisateur avec un mot de passe fort
   - Attendre la fin de l'installation
   - Redémarrer la VM

## 4. Configuration réseau

1. Créer un réseau interne :
```bash
VBoxManage natnetwork add --netname "EpiRootkit-Net" --network "192.168.15.0/24" --enable
```

2. Attacher les VMs au réseau :
```bash
VBoxManage modifyvm "EpiRootkit-Victim" --nic1 natnetwork --nat-network1 "EpiRootkit-Net"
VBoxManage modifyvm "EpiRootkit-Attacker" --nic1 natnetwork --nat-network1 "EpiRootkit-Net"
```

## 5. Configuration post-installation

### VM Victime
```bash
# Ouvrir un terminal (Ctrl+Alt+T)

# Mettre à jour le système
sudo apt update && sudo apt upgrade -y

# Configurer le nom d'hôte
sudo hostnamectl set-hostname epirootkit-victim
echo "127.0.1.1 epirootkit-victim" | sudo tee -a /etc/hosts

# Désactiver SELinux
sudo apt install -y selinux-utils
sudo setenforce 0
echo "SELINUX=disabled" | sudo tee /etc/selinux/config

# Désactiver Secure Boot
sudo mokutil --disable-validation

# Désactiver Kernel Lockdown
echo "kernel.lockdown=0" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Installer les dépendances nécessaires
sudo apt install -y build-essential linux-headers-$(uname -r) git

# Vérifier la version du kernel
uname -r  # Doit être >= 4.0.0, idéalement 5.15.0

# Cloner le projet EpiRootkit
git clone https://github.com/votre-repo/epirootkit.git
cd epirootkit

# Compiler et installer le rootkit
./start.sh
```

### VM Attaquant
```bash
# Ouvrir un terminal (Ctrl+Alt+T)

# Mettre à jour le système
sudo apt update && sudo apt upgrade -y

# Installer les dépendances nécessaires
sudo apt install -y python3 python3-pip git

# Cloner le projet EpiRootkit
git clone https://github.com/votre-repo/epirootkit.git
cd epirootkit

# Installer les dépendances Python
pip3 install -r requirements.txt
```

## 6. Vérification de la configuration

### Sur la VM Victime
```bash
# Vérifier que le module est chargé
lsmod | grep epirootkit

# Vérifier l'IP
ip addr show

# Vérifier la version du kernel
uname -r
```

### Sur la VM Attaquant
```bash
# Vérifier la connectivité
ping <IP_VICTIME>

# Tester la connexion au rootkit
python3 attacking_program/client.py <IP_VICTIME>
```

## 7. Sécurité et bonnes pratiques

### Sécurité
- Désactiver les mises à jour automatiques sur la VM Victime
- Configurer un pare-feu pour limiter l'accès
- Utiliser des mots de passe forts
- Sauvegarder régulièrement les VMs
- Documenter les configurations

### Bonnes pratiques
- Tester la configuration dans un environnement isolé
- Documenter toutes les modifications
- Créer des sauvegardes avant chaque modification majeure
- Utiliser des outils de monitoring pour détecter les anomalies
- Maintenir un journal des activités

## 8. Dépannage

### Problèmes courants
1. Module non chargé
   - Vérifier les logs : `dmesg | tail`
   - Vérifier la version du kernel : `uname -r`
   - Vérifier les headers : `ls /lib/modules/$(uname -r)/build`
2. Problèmes de réseau
   - Vérifier la configuration réseau : `ip addr show`
   - Tester la connectivité : `ping <IP_DESTINATION>`
   - Vérifier le pare-feu : `sudo ufw status`
3. Problèmes de compilation
   - Vérifier les dépendances : `make clean && make`
   - Vérifier les logs de compilation
   - Vérifier la version de gcc : `gcc --version`

## 9. Support

Pour toute question ou problème, veuillez :
1. Consulter la documentation du projet
2. Vérifier les logs système
3. Contacter l'équipe de support
