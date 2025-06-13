# Documentation : epirootkit_client.py

## Présentation

`epirootkit_client.py` est un client avancé permettant de contrôler à distance un rootkit via une connexion réseau sécurisée. Il agit comme un serveur d'attente : il écoute sur une adresse IP et un port donnés, puis attend qu'un agent/rootkit se connecte pour offrir une interface de commande interactive.

## Fonctionnalités principales
- **Connexion sécurisée** : Utilise AES-256-CBC pour chiffrer les échanges réseau.
- **Authentification** : Vérifie le mot de passe du rootkit lors de la connexion.
- **Upload/Download de fichiers** : Permet d'envoyer ou de récupérer des fichiers depuis la machine compromise.
- **Keylogger** : Démarre, arrête et récupère les frappes clavier à distance.
- **Gestion de redirections réseau** : Ajoute, supprime ou liste des règles de redirection de ports/IP.
- **Mise à jour du rootkit** : Permet d'envoyer un nouveau module pour mettre à jour le rootkit à distance.
- **Interface interactive** : Propose un prompt pour envoyer des commandes personnalisées.

## Utilisation

### Lancement
Dans un terminal, placez-vous dans le dossier contenant le script **sur la machine attaquante (attacker)** puis lancez :

```sh
python3 epirootkit_client.py --host 0.0.0.0 --port 4444
```
- `--host` : adresse IP locale d'écoute (par défaut 0.0.0.0)
- `--port` : port d'écoute (par défaut 4444)

### Commandes disponibles après connexion
- `upload chemin_local nom_distant` : envoie un fichier vers la machine compromise
- `download nom_distant chemin_local` : récupère un fichier depuis la machine compromise
- `keylog start` / `keylog stop` : démarre/arrête le keylogger
- `redirect add src_ip dst_ip src_port dst_port protocol` : ajoute une règle de redirection
- `redirect remove index` : supprime une règle de redirection
- `redirect list` : liste les règles de redirection
- `update chemin_module` : met à jour le rootkit
- `exit` : quitte le client
- Toute autre commande sera envoyée telle quelle au rootkit

## Dépendances
- Python 3
- cryptography

Installez les dépendances avec :
```sh
pip install -r requirements.txt
```

## Sécurité
- La clé de chiffrement doit être identique côté client et rootkit.
- Les échanges sont chiffrés pour éviter l'interception des commandes et des données.

## Remarques
- Ce client est destiné à des usages avancés et à des environnements de test ou de recherche en sécurité.
- Toute utilisation sur un système sans autorisation explicite est illégale.
