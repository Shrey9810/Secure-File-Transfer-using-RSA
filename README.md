# Secure File Transfer and Chatting Using RSA Encryption

## Overview
This project demonstrates a secure file transfer system where a sender transmits a file to a receiver using RSA encryption and digital signatures. The system employs socket programming to establish a TCP connection, exchange public keys, and securely transfer data in dynamically sized chunks. Additionally, a secure chat feature is implemented using the same encryption mechanism. This project ensures confidentiality, integrity, and authentication through RSA encryption and digital signatures.

## Features
- *RSA Encryption & Digital Signature:*  
  - The sender signs the file using its private key and then encrypts it using the receiver's public key.
  - The receiver first decrypts the file with its private key and then verifies the sender's signature using the sender's public key.
- *Socket Programming:*  
  - Implements TCP socket communication to establish a secure connection between the sender and receiver.
- *Dynamic Chunking:*  
  - Splits the file into appropriate chunks based on RSA key sizes to ensure proper encryption and decryption.
- *Key Exchange:*  
  - Secure exchange of public keys between sender and receiver to facilitate encrypted communication.
- *Secure Chat:*  
  - Implements an encrypted chat system between sender and receiver using RSA encryption.

## Technology Used
- *Python*  
- *Socket Programming* (TCP/IP)
- *Sympy* for prime generation and RSA key creation
- *RSA Algorithm* for encryption, decryption, and digital signatures

## Project Structure
- sender.py  
  Contains the implementation for the sender:
  - Generates RSA keys.
  - Signs the file using the sender's private key.
  - Encrypts the signed file using the receiver's public key.
  - Sends the encrypted file over a TCP connection.
  - Handles encrypted chat communication.
  
- receiver.py  
  Contains the implementation for the receiver:
  - Generates RSA keys.
  - Receives the encrypted file via TCP.
  - Decrypts the file using the receiver's private key.
  - Verifies the sender’s signature using the sender's public key.
  - Reconstructs and saves the original file.
  - Handles encrypted chat communication.

## Getting Started

### Prerequisites
- *Python 3.x* installed.
- Required Python packages:
  - sympy  
    Install using pip:
    ```sh
    pip install sympy
    ```

### Installation
1. *Clone the Repository:*
   ```sh
   git clone https://github.com/Shrey9810/Secure-File-Transfer-using-RSA.git
   cd Secure-File-Transfer-RSA
   ```
