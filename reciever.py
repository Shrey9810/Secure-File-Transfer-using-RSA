import sympy as sm
import random
import time
import math
import socket
import os
import hashlib

random.seed(time.time())

# Generate RSA keys for Receiver
random_number1 = random.getrandbits(1024)
p = sm.nextprime(random_number1)
while True:
    random_number2 = random.getrandbits(1024)
    q = sm.nextprime(random_number2)
    if p != q:
        break

n_r = p * q
phi_r = (p - 1) * (q - 1)

while True:
    e_r = random.randint(2, phi_r - 1)
    if math.gcd(e_r, phi_r) == 1:
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

d_r = mod_inverse(e_r, phi_r)

# TCP Server to Receive Encrypted File
def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))
    server_socket.listen(1)
    print("Waiting for sender connection...")

    conn, addr = server_socket.accept()
    print(f"Connected to sender {addr}")

    # Receive sender's public key
    sender_key_data = conn.recv(4096).decode()
    n_s, e_s = map(int, sender_key_data.split(','))
    print("Received sender's public key.")

    # Send receiver's public key
    conn.send(f"{n_r},{e_r}".encode())
    print("Sent receiver's public key.")

    # Receive the file name
    file_name = conn.recv(4096).decode()
    conn.send(b"ACK")  # Send acknowledgment

    # Receive the number of chunks
    num_chunks = int(conn.recv(4096).decode())
    conn.send(b"ACK")  # Send acknowledgment

    # Receive the comma-separated list of original chunk sizes
    sizes_str = conn.recv(4096).decode()
    chunk_sizes = list(map(int, sizes_str.split(',')))
    conn.send(b"ACK")  # Send acknowledgment

    encrypted_chunks = []
    signatures = []
    for _ in range(num_chunks):
        # Each payload is "encrypted_msg,signature"
        payload = conn.recv(4096).decode()
        enc_str, sig_str = payload.split(',')
        encrypted_chunks.append(int(enc_str))
        signatures.append(int(sig_str))
        conn.send(b"ACK")  # Send acknowledgment

    print("Received encrypted file.")

    # For each chunk, verify the signature and then decrypt with receiver's private key
    decrypted_data = b''
    for i, (encrypted_msg, signature) in enumerate(zip(encrypted_chunks, signatures)):
        # Recompute the hash of the ciphertext
        hash_obj = hashlib.sha256(str(encrypted_msg).encode())
        hash_val = int.from_bytes(hash_obj.digest(), 'big')
        # Verify signature: recover the hash from the signature using sender's public key
        recovered_hash = pow(signature, e_s, n_s)
        if recovered_hash != hash_val:
            print("Signature verification failed for a chunk.")
            return

        # Decrypt with receiver's private key
        msg_int = pow(encrypted_msg, d_r, n_r)
        # Convert integer back to bytes. Use the recorded chunk size.
        rec_bytes = msg_int.to_bytes((msg_int.bit_length() + 7) // 8, 'big')
        expected_length = chunk_sizes[i]
        if len(rec_bytes) < expected_length:
            rec_bytes = rec_bytes.rjust(expected_length, b'\x00')
        elif len(rec_bytes) > expected_length:
            rec_bytes = rec_bytes[-expected_length:]
        decrypted_data += rec_bytes

    # Save the decrypted file
    output_file_path = f"received_{file_name}"
    with open(output_file_path, "wb") as file:
        file.write(decrypted_data)

    print(f"Decrypted file saved as: {output_file_path}")
    conn.close()

if __name__ == "__main__":
    server()
