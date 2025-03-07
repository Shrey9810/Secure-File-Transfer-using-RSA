import sympy as sm
import random
import time
import math
import socket
import os

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

    cipher_chunks = []
    for _ in range(num_chunks):
        cipher_text = conn.recv(4096).decode()
        cipher_chunks.append(int(cipher_text))
        conn.send(b"ACK")  # Send acknowledgment

    print("Received encrypted file.")

    # First decryption: decrypt with receiver's private key
    decrypted_chunks = [pow(C, d_r, n_r) for C in cipher_chunks]

    # Second decryption: verify signature using sender's public key and recover original bytes
    decrypted_data = b''
    for i, C in enumerate(decrypted_chunks):
        # Recover the original message integer using sender's public key
        recovered_int = pow(C, e_s, n_s)
        # Convert recovered_int to bytes using its natural length
        rec_bytes = recovered_int.to_bytes((recovered_int.bit_length() + 7) // 8, 'big')
        expected_length = chunk_sizes[i]
        # If the recovered bytes are shorter than expected, pad on the left with zeros
        if len(rec_bytes) < expected_length:
            rec_bytes = rec_bytes.rjust(expected_length, b'\x00')
        # If they are longer than expected, trim the extra bytes from the left
        elif len(rec_bytes) > expected_length:
            rec_bytes = rec_bytes[-expected_length:]
        decrypted_data += rec_bytes

    # Save the decrypted file
    output_file_path = f"received_{file_name}"
    with open(output_file_path, "wb") as file:
        file.write(decrypted_data)

    print(f"\nDecrypted file saved as: {output_file_path}")
    conn.close()

if __name__ == "__main__":
    server()