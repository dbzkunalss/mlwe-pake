import socket
import json
import mlwe_crypto
import pake_protocol
import logging

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Server Configuration ---
HOST = '127.0.0.1'
PORT = 65432
SERVER_ID = "MyPakeServer"
# THIS IS A FIXED PASSWORD FOR THE DEMO CLIENT
# In reality, the server would look up the expected password hash/salt for the client_id
EXPECTED_CLIENT_PASSWORD = "correct-horse-battery-staple"

def run_server():
    # Generate Server's long-term KEM keys (or load them)
    # For this demo, we generate anew each time. Real server has persistent keys.
    server_pk, server_sk = mlwe_crypto.generate_kem_keys()
    logging.info(f"Server {SERVER_ID} started. Public KEM Key generated.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        logging.info(f"Server listening on {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            logging.info(f"Connected by {addr}")

            # --- PAKE Protocol Execution ---
            try:
                # 1. Receive Client Message 1
                data_bytes = conn.recv(4096) # Adjust buffer size as needed
                if not data_bytes:
                    raise ConnectionError("Client disconnected prematurely")
                logging.info("Server: Received Message 1 from client.")

                # 2. Process Client Message 1 & Create Server Message 1
                server_msg1, server_context, transcript = pake_protocol.process_client_message1(
                    data_bytes, SERVER_ID, server_sk, EXPECTED_CLIENT_PASSWORD
                )

                if server_msg1 is None:
                    logging.error("Server: PAKE Failed during Message 1 processing.")
                    # Optionally send an error message
                    conn.sendall(json.dumps({"type": "ERROR", "info": "PAKE Failed"}).encode('utf-8'))
                    return # End connection

                logging.info("Server: Sending Message 1 to client.")
                conn.sendall(json.dumps(server_msg1).encode('utf-8'))

                # Log server context before final key calculation
                logging.debug(f"Server context before final key calculation: {server_context}")

                # --- Final Key Derivation (Server Side) ---
                # (No more messages needed in this simplified protocol)
                final_server_key = pake_protocol.calculate_final_key(server_context, transcript)
                logging.info("\n-------------------------------------")
                logging.info(f"Server: PAKE Successful!")
                logging.info(f"Server: Final Derived Key (first 16 bytes): {final_server_key[:16].hex()}")
                logging.info("-------------------------------------\n")

                # TODO: Use the final_server_key for secure communication
                # e.g., encrypt/decrypt further messages using AES-GCM

            except (ConnectionError, json.JSONDecodeError, ValueError, Exception) as e:
                logging.error(f"Server Error during PAKE: {e}")
            finally:
                logging.info("Server: Closing connection.")

if __name__ == "__main__":
    run_server() 