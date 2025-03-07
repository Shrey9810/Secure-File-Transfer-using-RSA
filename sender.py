import sympy as sm
import random
import time
import math
import socket
import os

random.seed(time.time())

# Generate RSA keys for Sender
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

# TCP Client to Send Encrypted File
def sender():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('XXX.XXX.XXX.XXX', 12345))

    # Send sender's public key
    client_socket.send(f"{n_s},{e_s}".encode())
    print("Sent public key to receiver.")

    # Receive receiver's public key
    receiver_key_data = client_socket.recv(4096).decode()
    n_r, e_r = map(int, receiver_key_data.split(','))
    print("Received receiver's public key.")

    # Get file path
    file_path = input("Enter the file path to send: ")
    if not os.path.exists(file_path):
        print("Error: File does not exist.")
        return

    file_name = os.path.basename(file_path)
    client_socket.send(file_name.encode())  # Send file name
    client_socket.recv(1024)  # Acknowledgment

    with open(file_path, "rb") as file:
        file_content = file.read()

    # Determine the max chunk size dynamically
    max_chunk_size = min((n_s.bit_length() // 8) - 1, (n_r.bit_length() // 8) - 1)
    chunks = [file_content[i:i+max_chunk_size] for i in range(0, len(file_content), max_chunk_size)]
    # Record the original length for each chunk
    chunk_sizes = [len(chunk) for chunk in chunks]

    # Double Encryption: Sign with sender's private key, then encrypt with receiver's public key
    cipher_chunks = []
    for chunk in chunks:
        msg_int = int.from_bytes(chunk, 'big')
        signed_msg = pow(msg_int, d_s, n_s)      # Sign with sender's private key
        encrypted_msg = pow(signed_msg, e_r, n_r)  # Encrypt with receiver's public key
        cipher_chunks.append(str(encrypted_msg))

    # Send the number of chunks first
    client_socket.send(str(len(cipher_chunks)).encode())
    client_socket.recv(1024)  # Wait for acknowledgment

    # Send the comma-separated list of chunk sizes
    sizes_str = ','.join(map(str, chunk_sizes))
    client_socket.send(sizes_str.encode())
    client_socket.recv(1024)  # Wait for acknowledgment

    # Send encrypted chunks one by one
    for cipher in cipher_chunks:
        client_socket.send(cipher.encode())
        client_socket.recv(1024)  # Wait for acknowledgment

    print("Encrypted file sent successfully.")
    client_socket.close()

if __name__ == "__main__":
    sender()
