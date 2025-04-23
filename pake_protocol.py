import json
import base64
from mlwe_crypto import (
    generate_kem_keys, kem_encapsulate, kem_decapsulate,
    hash_password_simple, derive_final_secret, hash_transcript
)

# WARNING: THIS PAKE PROTOCOL IS A TOY EXAMPLE AND IS INSECURE.
# DO NOT USE IN PRODUCTION. FOR DEMONSTRATION PURPOSES ONLY.

# Simplified Message Structures (using dictionaries, could be JSON serialized)

def create_client_message1(client_id, password, server_kem_pk):
    """Creates the first client message."""
    # 1. Generate ephemeral KEM keys for the client
    client_pk, client_sk = generate_kem_keys()

    # 2. Process password (INSECURE METHOD - Placeholder)
    salt, password_hash = hash_password_simple(password)

    # 3. Encapsulate the password hash using the server's public key
    try:
        # First encapsulate without payload to get the shared secret
        ciphertext_cs, shared_secret_cs = kem_encapsulate(server_kem_pk)
        # Then encapsulate with the payload
        payload_to_encapsulate = salt + password_hash
        ciphertext_payload, _ = kem_encapsulate(server_kem_pk, payload_to_encapsulate)

    except Exception as e:
        print(f"Error during client KEM encapsulation: {e}")
        return None, None, None

    # 4. Construct message
    message = {
        "type": "CLIENT_MSG1",
        "client_id": client_id,
        "client_kem_pk": base64.b64encode(client_pk).decode('utf-8'),
        "ciphertext_payload": base64.b64encode(ciphertext_payload).decode('utf-8'),
        "salt": base64.b64encode(salt).decode('utf-8'),
    }

    # Keep client secret key and the KEM secret derived for later use
    client_context = {
        "client_sk": client_sk,
        "shared_secret_cs": shared_secret_cs
    }

    return message, client_context, [json.dumps(message, sort_keys=True).encode('utf-8')]

def process_client_message1(message_bytes, server_id, server_sk, expected_password):
    """Processes the first client message on the server."""
    try:
        message = json.loads(message_bytes.decode('utf-8'))
        if message.get("type") != "CLIENT_MSG1":
            raise ValueError("Invalid message type")

        client_id = message["client_id"]
        client_pk_b64 = message["client_kem_pk"]
        ciphertext_payload_b64 = message["ciphertext_payload"]
        salt_b64 = message["salt"]

        client_pk = base64.b64decode(client_pk_b64)
        ciphertext_payload = base64.b64decode(ciphertext_payload_b64)
        salt = base64.b64decode(salt_b64)

        # 1. Decapsulate the payload
        payload = kem_decapsulate(server_sk, ciphertext_payload)
        
        # Extract salt and password hash from the payload
        salt_received = payload[:len(salt)]
        password_hash_received = payload[len(salt):]

        if salt_received != salt:
            raise ValueError("Salt mismatch during decapsulation - protocol error!")

        # 2. Verify password
        _, expected_password_hash = hash_password_simple(expected_password, salt)
        if password_hash_received != expected_password_hash:
            print("Server: Password verification failed!")
            return None, None, None

        print("Server: Client password verified (using insecure method).")

        # 3. Generate server's response
        confirmation_payload = b"SERVER_CONFIRMATION"
        ciphertext_sc, shared_secret_sc = kem_encapsulate(client_pk, confirmation_payload)

        # 4. Construct response message
        response = {
            "type": "SERVER_MSG1",
            "server_id": server_id,
            "ciphertext_sc": base64.b64encode(ciphertext_sc).decode('utf-8'),
        }

        # Derive shared_secret_cs on the server side
        ciphertext_cs, shared_secret_cs = kem_encapsulate(client_pk)

        # Update server context to include shared_secret_cs
        server_context = {
            "shared_secret_sc": shared_secret_sc,
            "shared_secret_cs": shared_secret_cs
        }

        return response, server_context, [message_bytes, json.dumps(response, sort_keys=True).encode('utf-8')]

    except Exception as e:
        print(f"Server: Error processing client message: {e}")
        return None, None, None


def process_server_message1(message_bytes, client_context):
    """Processes the server's response on the client."""
    try:
        message = json.loads(message_bytes.decode('utf-8'))
        if message.get("type") != "SERVER_MSG1":
            raise ValueError("Invalid message type")

        server_id = message["server_id"]
        ciphertext_sc_b64 = message["ciphertext_sc"]
        ciphertext_sc = base64.b64decode(ciphertext_sc_b64)

        # 1. Decapsulate the server's confirmation/payload
        shared_secret_sc = kem_decapsulate(client_context["client_sk"], ciphertext_sc)
        # In this example, the payload was b"SERVER_CONFIRMATION"
        # A real protocol might check this value.
        print(f"Client: Received server confirmation payload (secret length {len(shared_secret_sc)})")


        # Client context now holds both necessary secrets
        final_client_context = {
             "shared_secret_cs": client_context["shared_secret_cs"],
             "shared_secret_sc": shared_secret_sc,
        }
        transcript_update = [message_bytes]
        return final_client_context, transcript_update

    except Exception as e:
        print(f"Client error processing server message: {e}")
        return None, None

def calculate_final_key(context, transcript_messages):
     """Calculates the final shared key on either side."""
     transcript_hash = hash_transcript(transcript_messages)
     # Ensure keys are used in a consistent order for derivation
     key = derive_final_secret(context["shared_secret_cs"], context["shared_secret_sc"], transcript_hash)
     return key 