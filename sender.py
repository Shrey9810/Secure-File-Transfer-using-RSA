import sympy as sm
import random
import time
import math
import socket
import os
import hashlib
import threading

random.seed(time.time())

# Generate RSA keys for the client (sender)
random_number1 = random.getrandbits(1024)
p = sm.nextprime(random_number1)
while True:
    random_number2 = random.getrandbits(1024)
    q = sm.nextprime(random_number2)
    if p != q:
        break

n_s = p * q
phi_s = (p - 1) * (q - 1)
while True:
    e_s = random.randint(2, phi_s - 1)
    if math.gcd(e_s, phi_s) == 1:
        break

def extended_euclid(a, b):
    x, y, x_last, y_last = 1, 0, 0, 1
    while a != 0:
        q, r = divmod(b, a)
        m, n = x_last - q * x, y_last - q * y
        x_last, y_last, x, y = x, y, m, n
        b, a = a, r
    return b, x_last, y_last

def mod_inverse(a, m):
    gcd, x, _ = extended_euclid(a, m)
    if gcd != 1:
        return -1
    return (x + m) % m

d_s = mod_inverse(e_s, phi_s)

# Global variables for the remote (server)'s public key.
remote_n = None
remote_e = None

# Helper to send a line (adds newline)
def send_line(sock, line):
    sock.sendall((line + "\n").encode())

# Thread to continuously receive messages
def receive_thread(sock):
    fileobj = sock.makefile('r')
    try:
        while True:
            line = fileobj.readline()
            if not line:
                print("Connection closed.")
                break
            line = line.rstrip("\n")
            # Process encrypted chat messages:
            if line.startswith("ENC_CHAT:"):
                data = line[len("ENC_CHAT:"):]
                try:
                    enc_str, sig_str = data.split(",", 1)
                    enc_msg = int(enc_str)
                    signature = int(sig_str)
                except Exception as ex:
                    print("Error parsing chat message:", ex)
                    continue
                # Verify signature using remote's public key
                computed_hash = int.from_bytes(hashlib.sha256(str(enc_msg).encode()).digest(), 'big')
                recovered_hash = pow(signature, remote_e, remote_n)
                if recovered_hash != computed_hash:
                    print("Chat signature verification failed.")
                    continue
                # Decrypt with our private key (client’s d_s, n_s)
                msg_int = pow(enc_msg, d_s, n_s)
                msg_bytes = msg_int.to_bytes((msg_int.bit_length() + 7) // 8, 'big')
                try:
                    text = msg_bytes.decode()
                except:
                    text = "<Decoding error>"
                print("Peer (chat):", text)
            # Process file transfers:
            elif line.startswith("FILE_HEADER:"):
                # Format: FILE_HEADER:<filename>:<num_chunks>:<chunk_sizes>
                parts = line.split(":", 3)
                if len(parts) < 4:
                    print("Malformed file header.")
                    continue
                filename = parts[1]
                num_chunks = int(parts[2])
                chunk_sizes = list(map(int, parts[3].split(",")))
                print(f"Receiving file '{filename}' with {num_chunks} chunks.")
                encrypted_chunks = []
                signatures = []
                for _ in range(num_chunks):
                    chunk_line = fileobj.readline().rstrip("\n")
                    if not chunk_line.startswith("FILE_CHUNK:"):
                        print("Expected FILE_CHUNK, got:", chunk_line)
                        break
                    data = chunk_line[len("FILE_CHUNK:"):]
                    try:
                        enc_str, sig_str = data.split(",", 1)
                        encrypted_chunks.append(int(enc_str))
                        signatures.append(int(sig_str))
                    except Exception as ex:
                        print("Error parsing file chunk:", ex)
                # Read file terminator
                end_line = fileobj.readline().rstrip("\n")
                if end_line != "FILE_END":
                    print("Missing file end marker.")
                    continue
                # Process each chunk: verify signature then decrypt.
                decrypted_data = b''
                for i, (encrypted_msg, signature) in enumerate(zip(encrypted_chunks, signatures)):
                    hash_obj = hashlib.sha256(str(encrypted_msg).encode())
                    hash_val = int.from_bytes(hash_obj.digest(), 'big')
                    recovered_hash = pow(signature, remote_e, remote_n)
                    if recovered_hash != hash_val:
                        print("File chunk signature verification failed.")
                        break
                    # Decrypt with our private key (client’s d_s, n_s)
                    msg_int = pow(encrypted_msg, d_s, n_s)
                    rec_bytes = msg_int.to_bytes((msg_int.bit_length() + 7) // 8, 'big')
                    expected_length = chunk_sizes[i]
                    if len(rec_bytes) < expected_length:
                        rec_bytes = rec_bytes.rjust(expected_length, b'\x00')
                    elif len(rec_bytes) > expected_length:
                        rec_bytes = rec_bytes[-expected_length:]
                    decrypted_data += rec_bytes
                out_filename = f"received_{filename}"
                with open(out_filename, "wb") as f:
                    f.write(decrypted_data)
                print(f"File '{filename}' received and saved as '{out_filename}'.")
            else:
                print("Unknown message:", line)
    except Exception:
        print("Connection closed.")

def main():
    global remote_n, remote_e
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Change IP/port as needed.
    sock.connect(('XXX.XXX.XXX.XXX', 12345)) #Change with Reciever's IP Address (Both Clients should be connected to same network)

    # --- Key Exchange ---
    # Send our public key (client's keys)
    send_line(sock, f"{n_s},{e_s}")
    # Receive remote public key (server's keys)
    remote_key_line = sock.recv(4096).decode().strip()
    try:
        remote_n, remote_e = map(int, remote_key_line.split(','))
    except Exception as ex:
        print("Error parsing remote public key:", ex)
        return
    print("Exchanged public keys.")
    # Start receiver thread.
    threading.Thread(target=receive_thread, args=(sock,), daemon=True).start()

    print("You can now chat and send files. Type '/file' to send a file, '/exit' to exit.")
    while True:
        user_input = input()
        if user_input.strip() == "":
            continue
        if user_input.lower() == "/exit":
            send_line(sock, "ENC_CHAT:" + f"{0},{0}")  # dummy message; connection will close
            break
        elif user_input.lower() == "/file":
            file_path = input("Enter the file path to send: ")
            if not os.path.exists(file_path):
                print("File does not exist.")
                continue
            file_name = os.path.basename(file_path)
            with open(file_path, "rb") as f:
                file_content = f.read()
            # Determine max chunk size for RSA encryption.
            max_chunk_size = (remote_n.bit_length() // 8) - 1
            chunks = [file_content[i:i+max_chunk_size] for i in range(0, len(file_content), max_chunk_size)]
            chunk_sizes = [len(chunk) for chunk in chunks]
            encrypted_chunks = []
            signatures = []
            for chunk in chunks:
                msg_int = int.from_bytes(chunk, 'big')
                # Encrypt with remote's public key
                enc_msg = pow(msg_int, remote_e, remote_n)
                hash_obj = hashlib.sha256(str(enc_msg).encode())
                hash_val = int.from_bytes(hash_obj.digest(), 'big')
                # Sign with our private key
                signature = pow(hash_val, d_s, n_s)
                encrypted_chunks.append(str(enc_msg))
                signatures.append(str(signature))
            num_chunks = len(encrypted_chunks)
            header = f"FILE_HEADER:{file_name}:{num_chunks}:{','.join(map(str, chunk_sizes))}"
            send_line(sock, header)
            for enc, sig in zip(encrypted_chunks, signatures):
                send_line(sock, f"FILE_CHUNK:{enc},{sig}")
            send_line(sock, "FILE_END")
            print(f"File '{file_name}' sent.")
        else:
            # --- Encrypt and sign a chat message ---
            msg_bytes = user_input.encode()
            msg_int = int.from_bytes(msg_bytes, 'big')
            # Encrypt with remote's public key (server's)
            enc_msg = pow(msg_int, remote_e, remote_n)
            hash_obj = hashlib.sha256(str(enc_msg).encode())
            hash_val = int.from_bytes(hash_obj.digest(), 'big')
            signature = pow(hash_val, d_s, n_s)
            send_line(sock, f"ENC_CHAT:{enc_msg},{signature}")
    sock.close()
    print("Connection closed.")

if __name__ == "__main__":
    main()
