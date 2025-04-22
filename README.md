
# MLWE-PAKE Implementation

This project is a demonstration of a Password-Authenticated Key Exchange (PAKE) protocol using the Module Learning With Errors (MLWE) cryptographic primitive. It is designed for educational purposes and should not be used in production environments.

## Overview

The implementation consists of a client-server model where both parties authenticate each other using a shared password and establish a secure communication channel. The protocol uses Key Encapsulation Mechanisms (KEM) from the liboqs library to perform cryptographic operations.

### Simulating a TLS Handshake

This implementation simulates the key exchange and authentication phases of a TLS handshake using a PAKE protocol. In a typical TLS handshake, the client and server exchange cryptographic keys and authenticate each other to establish a secure session. Similarly, in this PAKE protocol:

1. **Key Exchange**: The client and server exchange public keys and encapsulate shared secrets using the Kyber KEM algorithm. This mimics the key exchange phase of a TLS handshake.

2. **Authentication**: Both parties authenticate each other using a shared password, similar to how certificates are used in TLS to verify identities.

3. **Session Key Derivation**: A final shared key is derived from the exchanged messages, analogous to the session key derived in a TLS handshake for encrypting subsequent communication.

### Key Components

1. **mlwe_crypto.py**: Handles cryptographic operations such as key generation, encapsulation, and decapsulation using the Kyber KEM algorithm. It also includes simple password hashing and secret derivation functions.

2. **pake_protocol.py**: Implements the PAKE protocol logic, including message creation, processing, and final key derivation. It uses the cryptographic functions from `mlwe_crypto.py`.

3. **pake_client.py**: The client-side script that initiates the PAKE protocol with the server. It requires the server's public key to start the process.

4. **pake_server.py**: The server-side script that listens for client connections and processes the PAKE protocol. It generates a public/private key pair for the KEM operations.

## How It Works

1. **Key Generation**: The server generates a public/private key pair for the KEM operations. The public key is shared with the client.

2. **Client Message 1**: The client generates its own ephemeral key pair and encapsulates a hashed version of the password using the server's public key. This message is sent to the server.

3. **Server Message 1**: The server decapsulates the received message to verify the password and encapsulates a confirmation message using the client's public key. This message is sent back to the client.

4. **Key Derivation**: Both the client and server derive a final shared key from the exchanged messages, which can be used for secure communication.

## Setup Instructions

### Prerequisites

- Python 3.6 or higher
- Virtual environment (recommended)

### Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Set up a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Server

1. **Start the server**:
   ```bash
   python pake_server.py
   ```

2. **Note the server's public key**: When the server starts, it will output a base64-encoded public key. Copy this key for the client setup.

### Running the Client

1. **Set the server's public key**: Open `pake_client.py` and replace the `SERVER_PK_B64` placeholder with the server's public key.

2. **Start the client**:
   ```bash
   python pake_client.py
   ```


