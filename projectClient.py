import socket
import rsa
from cryptography.fernet import Fernet

# Caesar Cipher Helper Functions
def caesar_encrypt(text, shift=3):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char 
    return result

def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)

# Generate RSA keys
client_public_key, client_private_key = rsa.newkeys(2048)

# Connect to server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 6677))

# Step 1: Send start-up packet for communication
start_packet = "(SS,RFMP,v1.0,1)" #'v1.0.1' indicates packets are encrypted
client_socket.send(start_packet.encode())
print(f"Packet sent: {start_packet}")

# Step 2: Receive and process server confirmation packet
confirmation_response = client_socket.recv(1024).decode()
print(f"Packet received: {confirmation_response}")
server_public_key = rsa.PublicKey.load_pkcs1(confirmation_response.split(",", 1)[1].encode())

# Step 3: Choose encryption algorithm and send encryption packet
algorithm = input("Choose encryption algorithm (AES/Caesar): ").strip().upper()
while algorithm not in ["AES", "CAESAR"]:
    algorithm = input("Invalid choice. Please choose AES or Caesar: ").strip().upper()

# Generate session key when AES is selected
session_key = Fernet.generate_key() if algorithm == "AES" else "ABC123"
encryption_packet = f"(EC,{algorithm},{session_key.decode() if algorithm == 'AES' else session_key},{client_public_key.save_pkcs1().decode()})"
client_socket.send(encryption_packet.encode())
print(f"Packet sent: {encryption_packet}")

cipher_suite = Fernet(session_key) if algorithm == "AES" else None

# Command processing: handles user input
while True:
    command = input("Enter command (or 'end' to quit): ").strip()
    if command.lower() == "end":
        end_packet = "(End)" # Indicates seesion termination
        encrypted_end_packet = cipher_suite.encrypt(end_packet.encode()) if cipher_suite else end_packet.encode()
        client_socket.send(encrypted_end_packet)
        print(f"Packet sent: {end_packet}")
        break


    # Construct packet for each command
    packet = ""
    if command.startswith("mkdir") or command.startswith("rmdir") or command.startswith("cd") or command.startswith("del") or command.startswith("ren") or command.startswith("ls") or command.startswith("cd..") or command.startswith("cp") or command.startswith("mv") or command.startswith("rm"):
        packet = f"(CM,prompt,{command})" # Formats the commands for server
    elif command.startswith("openWrite"):
        filename = command.split(" ", 1)[1]
        packet = f"(CM,openWrite {filename})"
    elif command.startswith("openRead"):
        filename = command.split(" ", 1)[1]
        packet = f"(CM,openRead {filename})"
    elif command.startswith("closeWrite"):
        packet = "(CM,closeWrite)"

    # Encrypt and send the packet
    if packet:
        encrypted_packet = cipher_suite.encrypt(packet.encode()) if cipher_suite else packet.encode()
        client_socket.send(encrypted_packet)
        print(f"Packet sent: {packet}")

        # Receive and decrypt the server's response
        encrypted_response = client_socket.recv(1024)
        response = cipher_suite.decrypt(encrypted_response).decode() if cipher_suite else encrypted_response.decode()
        print(f"Packet received: {response}")

        # Handle specific responses
        if command.startswith("openWrite") and response.startswith("SC"):
            # Prompt user to write data to the file
            data = input("Enter data to write to the file: ")
            data_packet = f"(DP,{data})"
            encrypted_data_packet = cipher_suite.encrypt(data_packet.encode()) if cipher_suite else data_packet.encode()
            client_socket.send(encrypted_data_packet)
            print(f"Packet sent: {data_packet}")

            # Wait for confirmation
            encrypted_response = client_socket.recv(1024)
            response = cipher_suite.decrypt(encrypted_response).decode() if cipher_suite else encrypted_response.decode()
            print(f"Packet received: {response}")

        elif command.startswith("openRead") and response.startswith("SC"):
            # Handle file content
            try:
                _, content = response.split(",", 1)
                print(content)
            except Exception as e:
                print(f"Error processing content: {e}")


    else:
        print("Invalid command. Please try again.")



