# Echover (Project 2 – Topic 2)

This repository is a minimal end-to-end encrypted (E2EE) group chat implementation in Python, matching the requirements of the Echover assignment.

## Implemented functionality

### Central server
- User registration + authentication (passwords stored as salted SHA-256).
- Stores users, groups, membership in SQLite.
- Routes messages A → Server → Group members.
- Cannot read group message plaintext: group payloads are E2EE ciphertext.

### User / client
- Register and login to server.
- Create a group, join a group, leave a group.
- Send E2EE group messages that only group members can decrypt.
- Join after chat started: on a member join event, the group owner automatically rotates the group key to a new epoch and distributes it to all active members.
- New members receive only the latest epoch key, so they cannot decrypt older ciphertext.
- Leave group: on a member leave event, the owner rotates and distributes a new epoch key to remaining members.
- The leaving member does not receive the new key and cannot decrypt future ciphertext.

## Cryptographic design

- Transport security: client↔server runs over TLS (self-signed cert).
- Group message E2EE: each group epoch has one symmetric key "K_G,epoch".
  - Confidentiality: AES-256 in CTR mode.
  - Integrity/authentication: HMAC-SHA256.
  - Composition: Encrypt-then-MAC (EtM).
  - The server routes {nonce_prefix, counter, ciphertext, tag} as opaque bytes.
- Key distribution:
  - Each user has an RSA-2048 keypair.
  - The group owner wraps the 32-byte epoch key for each member using RSA: c = m^e mod N.
  - Key update messages are signed using RSA signature: s = H(m)^d mod N with SHA-256.

## Repository

.
├── README.md
├── certs/                 # server.crt + server.key (generated with openssl on first server start)
├── src/
│   ├── __init__.py
│   ├── client.py
│   ├── crypto.py
│   ├── protocol.py
│   └── server.py
└── keys/                  # created at runtime

## Requirements

- Python 3.10+
- Python package: "pycryptodome"

Install:
python -m pip install -r requirements.txt

## How to run

### Terminal 1: start the server
From the repository root:

python -m src.server --host 127.0.0.1 --port 8443

First run generates:
- ./certs/server.crt
- ./certs/server.key

### Terminal 2: register Alice

python -m src.client --host 127.0.0.1 --port 8443 --register --username alice

Choose a password when prompted. This creates:
- ./keys/alice_private.json (AES-CTR + HMAC, key derived from the password)
- ./keys/alice_public.pem
- ./keys/alice_groupkeys.json (created later)

### Terminal 3: register Bob

python -m src.client --host 127.0.0.1 --port 8443 --register --username bob

### Terminal 2: login Alice and create a group

python -m src.client --host 127.0.0.1 --port 8443 --username alice

Commands:
> create testgroup
> groups

Copy the printed `group_id`.

### Terminal 3: login Bob and join the group

python -m src.client --host 127.0.0.1 --port 8443 --username bob

> join <group_id>

Alice will automatically rekey and send Bob the group key update. Bob will print:
- "Stored group key for <group_id> epoch <n> ..."

### Send messages
Alice:
> send <group_id> hello bob

Bob should see the plaintext, while the server only routes ciphertext.

Additionally, the server cannot read group messages because they are encrypted again at the application layer using AES-CTR + HMAC (EtM).

## Limitation

- The group owner is the only key-rotator, owners cannot leave in this demo.
