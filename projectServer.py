import socket
import os
import rsa
import threading
from cryptography.fernet import Fernet

# Generate RSA keys
(public_key, private_key) = rsa.newkeys(2048)

# Global variables
SESSION_KEY = None
cipher_suite = None
open_files = {}

def caesar_encrypt(text, shift=3):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char # Leaves non-aphabetic characters unchanged
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

def handle_client(client_socket, client_address):
    global SESSION_KEY, cipher_suite
    print(f"Client connected: {client_address}") # Logs client connection

    try:
        # Step 1: Receive and process the startup packet
        start_packet = client_socket.recv(1024).decode() # Wait for client to send data
        print(f"Packet received: {start_packet}")
        encryption_required = start_packet.endswith(",1)")

        # Step 2: Send confirmation packet
        if encryption_required:
            confirmation_packet = f"(CC,{public_key.save_pkcs1().decode()})"
        else:
            confirmation_packet = "(CC)"
        client_socket.send(confirmation_packet.encode())
        print(f"Packet sent: {confirmation_packet}")

        # Step 3: If no encryption is required, directly move to command handling
        if not encryption_required:
            print("Encryption not required. Ready for commands.")
        else:
            # Wait for encryption packet
            encryption_packet = client_socket.recv(1024).decode()
            print(f"Packet received: {encryption_packet}")

            if encryption_packet.startswith("(EC,"):
                parts = encryption_packet.strip("()").split(",", 3) # Extracts algorithm and session key
                if len(parts) >= 3:
                    algorithm, session_key_data, _ = parts[1:]
                    SESSION_KEY = session_key_data if algorithm == "Caesar" else session_key_data.encode()
                    cipher_suite = Fernet(SESSION_KEY) if algorithm == "AES" else None
                    print("Encryption setup completed.")
                else:
                    raise ValueError("Invalid encryption packet format.")
            else:
                raise ValueError("Expected encryption packet but received something else.")

        # Step 4: Handle commands from the client
        print("Ready for commands.")
        while True:
            encrypted_command = client_socket.recv(1024) # Recieve transfered data form client
            if not encrypted_command:
                break # Exit loop if connected is terminated

            decrypted_packet = cipher_suite.decrypt(encrypted_command).decode() if cipher_suite else encrypted_command.decode()
            print(f"Packet received: {decrypted_packet}")

            if decrypted_packet == "(End)":
                print("Closing connection as requested by the client.")
                break

            response = process_command(decrypted_packet)
            encrypted_response = cipher_suite.encrypt(response.encode()) if cipher_suite else response.encode()
            client_socket.send(encrypted_response)
            print(f"Packet sent: {response}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()


def process_command(command_packet):
    try:
        if command_packet.startswith("(CM,prompt,"):
            # Handle system-level commands
            command = command_packet.strip("()").split(",", 2)[2]
            if command.startswith("mkdir"):
                # Create directory
                folder = command.split(" ", 1)[1]
                os.mkdir(folder)
                return "SC,Folder created successfully."
            elif command.startswith("rmdir") or command.startswith("rd"):
                # Remove directory
                folder = command.split(" ", 1)[1]
                os.rmdir(folder)
                return "SC,Folder removed successfully."
            elif command.startswith("cd.."):
                os.chdir("..")  # Move one level up in the directory hierarchy
                return f"SC,Changed directory to {os.getcwd()}."
            elif command.startswith("ls"):
                # List directory contents
                path = command.split(" ", 1)[1] if len(command.split(" ", 1)) > 1 else "."
                files = os.listdir(path)
                return f"SC,Contents: {', '.join(files)}"
            elif command.startswith("cp"):
                # Copy file
                source, destination = command.split(" ")[1:3]
                with open(source, "rb") as src_file:
                    with open(destination, "wb") as dest_file:
                        dest_file.write(src_file.read())
                return "SC,File copied successfully."
            elif command.startswith("mv"):
                # Move/rename file
                source, destination = command.split(" ")[1:3]
                os.rename(source, destination)
                return "SC,File moved successfully."
            elif command.startswith("rm"):
                # Remove file
                file = command.split(" ", 1)[1]
                os.remove(file)
                return "SC,File removed successfully."
            elif command.startswith("cd"):
                # Change directory
                path = command.split(" ", 1)[1]
                os.chdir(path)
                return f"SC,Changed directory to {os.getcwd()}."
            elif command.startswith("del"):
                # Delete object
                file = command.split(" ", 1)[1]
                os.remove(file)
                return "SC,File deleted successfully."
            elif command.startswith("ren"):
                # Rename object
                old_name, new_name = command.split(" ")[1:]
                os.rename(old_name, new_name)
                return "SC,Renamed successfully."
            else:
                return "EE,Unsupported system command."
        elif command_packet.startswith("(CM,openWrite"):
            filename = command_packet.split(" ", 1)[1]
            open_files["current"] = open(filename, "w")
            return "SC,File opened for writing."
        elif command_packet.startswith("(CM,openRead"):
            filename = command_packet.split(" ", 1)[1]
            if os.path.exists(filename):
                with open(filename, "r") as f:
                    content = f.read()
                if cipher_suite:  # AES Encryption
                    content = cipher_suite.encrypt(content.encode()).decode()
                    return f"SC,File content: {cipher_suite.decrypt(content.encode()).decode()}"
                elif 'caesar' in locals() or 'caesar' in globals():  # Caesar Cipher
                    content = caesar_encrypt(content)
                    return f"SC,File content: {content}"
                else:  # No encryption (unencrypted communication)
                    return f"SC,File content: {content}"

            else:
                return "EE,File not found."

        elif command_packet.startswith("(CM,closeWrite"):
            if "current" in open_files:
                open_files["current"].close()
                del open_files["current"]
                return "SC,File closed successfully."
            else:
                return "EE,No file open to close."
        elif command_packet.startswith("(DP,"):
            data = command_packet.strip("()").split(",", 1)[1]
            if "current" in open_files:
                open_files["current"].write(data + "\n")
                return "SC,Data written successfully."
            else:
                return "EE,No file open for writing."
        else:
            return "EE,Invalid command."
    except Exception as e:
        return f"EE,{str(e)}"

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 6677))
server_socket.listen(5)
print("Server started. Waiting for connections...")

while True:
    client_socket, client_address = server_socket.accept()
    client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
    client_thread.start()


