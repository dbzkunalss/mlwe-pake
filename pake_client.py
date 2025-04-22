import socket
import json
import base64
import mlwe_crypto
import pake_protocol

# --- Client Configuration ---
HOST = '127.0.0.1' # The server's hostname or IP address
PORT = 65432        # The port used by the server
CLIENT_ID = "DemoClient123"
PASSWORD = "correct-horse-battery-staple" # The password to authenticate with

# Server's Public KEM Key - needed by the client to start the protocol
# In a real system, this would be pre-configured or obtained securely.
# FOR DEMO: We assume the client somehow knows the server's PK generated when server starts.
# You MUST copy the public key output by the server when it starts and paste it here (base64 encoded).
# Example placeholder - REPLACE THIS WITH ACTUAL SERVER PK OUTPUT:
SERVER_PK_B64 = "REPLACE_THIS_WITH_ACTUAL_SERVER_PUBLIC_KEY"
def run_client():
    try:
        server_pk = base64.b64decode(SERVER_PK_B64)
        if not server_pk or SERVER_PK_B64.startswith("REPLACE"):
             print("ERROR: Server Public KEM Key not set in pake_client.py!")
             print("Run the server first, copy its base64 public key, and paste it into the SERVER_PK_B64 variable.")
             return
    except Exception as e:
        print(f"Error decoding server public key: {e}. Is it correct base64?")
        return


    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            print(f"Client connecting to {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            print("Client: Connected.")

            # --- PAKE Protocol Execution ---
            # 1. Create and Send Client Message 1
            client_msg1, client_context, transcript = pake_protocol.create_client_message1(
                CLIENT_ID, PASSWORD, server_pk
            )
            if client_msg1 is None:
                print("Client: Failed to create Message 1.")
                return

            print("Client: Sending Message 1 to server.")
            s.sendall(json.dumps(client_msg1).encode('utf-8'))

            # 2. Receive Server Message 1
            data_bytes = s.recv(4096) # Adjust buffer size as needed
            if not data_bytes:
                 raise ConnectionError("Server disconnected prematurely")
            print("Client: Received Message 1 from server.")

            # Check for explicit error message from server
            try:
                possible_error = json.loads(data_bytes.decode('utf-8'))
                if possible_error.get("type") == "ERROR":
                     print(f"Client: Received error from server: {possible_error.get('info')}")
                     return
            except json.JSONDecodeError:
                 pass # Not an error message, proceed

            # 3. Process Server Message 1
            final_client_context, transcript_update = pake_protocol.process_server_message1(
                 data_bytes, client_context
            )
            transcript.extend(transcript_update) # Add server message to transcript

            if final_client_context is None:
                print("Client: PAKE Failed during Message 1 processing.")
                return

            # --- Final Key Derivation (Client Side) ---
            final_client_key = pake_protocol.calculate_final_key(final_client_context, transcript)
            print("\n-------------------------------------")
            print(f"Client: PAKE Successful!")
            print(f"Client: Final Derived Key (first 16 bytes): {final_client_key[:16].hex()}")
            print("-------------------------------------\n")

            # TODO: Use the final_client_key for secure communication

        except (ConnectionRefusedError, ConnectionResetError, TimeoutError) as e:
             print(f"Client Network Error: {e}")
        except (json.JSONDecodeError, ValueError, Exception) as e:
             print(f"Client Error during PAKE: {e}")
        finally:
             print("Client: Closing connection.")


if __name__ == "__main__":
    if SERVER_PK_B64.startswith("REPLACE"):
         print("ERROR: Server Public KEM Key not set in pake_client.py!")
         print("Run the server first, copy its base64 public key output, and paste it into the SERVER_PK_B64 variable at the top of this script.")
    else:
        run_client() 