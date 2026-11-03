# Secure Messaging System: README

<!--
HOW TO COMPLETE THIS FILE
- Replace every ___ with your own answer. 
- Keep answers short: one or two sentences is usually enough.
- "Where" means the file, the function, and the line numbers, e.g. messaging_client.py, protect_message, lines 120-138
  Check the line numbers are correct in the version you submit.
- If you have not fully met a requirement, say so and explain what is missing.
-->

---

## 1. Keys

List every key or key pair your system uses, one per row. The first row is a
worked example showing the level of detail expected; replace it with your own.

| Key | Algorithm | Long-term or short-term? | Held by | Used for | Created in (file, function, lines) |
|---|---|---|---|---|---|
| *(example)* User encryption key pair | RSA | Long-term | Each user (private); others hold the public half | Encrypting messages to this user so only the user can decrypt | messaging_client.py, create_identity, lines 00-00 |
This is only an example of the detail and format expected, not a suggested design.
| ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ |
| ___ | ___ | ___ | ___ | ___ | ___ |

---

## 2. Security requirements

For each requirement, explain in one or two sentences how your design meets it, then point to the code that does it. 
If you did not fully meet it, say what is missing instead.

### SR1: Secure channel to the server
> Traffic between a client and the server is confidential and cannot be modified undetected, and a client can tell it is talking to the genuine server rather than an impostor.

| | |
|---|---|
| How your design meets this | ___ |
| Where (file, function, lines) | ___ |

### SR2: The server can authenticate a client
> A user cannot make requests as another user.

| | |
|---|---|
| How your design meets this | ___ |
| Where (file, function, lines) | ___ |

### SR3: Two clients establish a shared secret key
> Two clients can establish a shared secret key that the server, and anyone else, cannot learn.

| | |
|---|---|
| How your design meets this | ___ |
| Where (file, function, lines) | ___ |

### SR4: Two clients can authenticate each other
> Each client can verify the identity of the other.

| | |
|---|---|
| How your design meets this | ___ |
| Where (file, function, lines) | ___ |

### SR5: Message confidentiality and integrity
> Message contents are confidential and their integrity is protected against both a network attacker and a curious server. Only the two clients, and not the server, can read or alter the message contents undetected.

| | |
|---|---|
| How your design meets this | ___ |
| Where (file, function, lines) | ___ |

---
