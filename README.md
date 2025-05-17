# RFMP-SecureFileManager
A secure file management client-server system using socket programming and encryption (AES &amp; Caesar cipher)
# CSEC201 - Secure RFMP (Remote File Management Protocol)

This project is developed as part of the CSEC-201 Programming for Information Security course (Fall 2024). 
It implements a custom **Remote File Management Protocol (RFMP)** over sockets in Python, enabling remote command
execution and secure file/folder management on a server system.

---

## 🔐 Features

- Client-server communication over TCP sockets
- Three-phase protocol: Setup, Operation, and Closing
- **Encryption support**:
  - **AES (Fernet)** for secure symmetric encryption
  - **Caesar Cipher** for lightweight encryption
  - **RSA** for secure session key exchange
- File and folder operations:
  - `mkdir`, `cd`, `rmdir/rd`, `del`, `ren`
  - `openRead`, `openWrite`, `closeWrite`
  - Extra commands like `ls`, `cp`, `mv`, `rm`
- Handles command responses and server-side exceptions
- Supports encrypted transfer of file data between client and server

---

## 🧱 Protocol Overview

### 1. Setup Phase
- Client sends a **Start Packet**: `(SS,RFMP,v1.0,[0|1])`
- Server responds with a **Confirmation Packet**: `(CC[,Server_Public_Key])`
- If encryption is required:
  - Client generates:
    - RSA key pair
    - Session key (AES or Caesar)
  - Sends **Encryption Packet**: `(EC,Algorithm,Encrypted_Session_Key,Client_Public_Key)`

### 2. Operation Phase
- Client sends commands in the format: `(CM,prompt,<command>)`
- For file operations: `(CM,openWrite <filename>)`, `(CM,openRead <filename>)`
- For sending file content: `(DP,<data>)`
- Server responds with:
  - `(SC,<message>)` for success
  - `(EE,<ErrorCode>,<Description>)` for errors

### 3. Closing Phase
- Client sends an **End Packet**: `(End)`
- Server terminates the session
