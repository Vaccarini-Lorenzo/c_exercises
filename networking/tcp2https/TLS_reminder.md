
 Starting point

 TCP handshake is done. We have a raw socket — a pipe of bytes between us and the server. Anyone sniffing the network can read everything we send. There's no encryption, no identity verification. Just raw bytes flowing.

 We want two things:
 1. Know we're talking to the real server (not an attacker)
 2. Encrypt everything so nobody can read it

 TLS achieves both. Here's the full flow, step by step.

 ────────────────────────────────────────────────────────────────────────────────

 Step 0: What we need to understand first

 Before TLS starts, two things exist in the world:

 The server has:
 - An RSA private key (a secret number, stored on the server, never shared)
 - A certificate (a file that says: "this RSA public key belongs to *.azurewebsites.net", signed by a Certificate Authority that everyone trusts)

 We have:
 - Nothing. We don't know the server yet. We just have a TCP socket.

 ────────────────────────────────────────────────────────────────────────────────

 Step 1: ClientHello — "Hi, let's talk securely"

 We send the first message. It's not encrypted (can't be — we don't have keys yet). It contains:

 - Client random (32 bytes) — a number we generate randomly. We'll need this later to derive encryption keys. It's not secret — it travels in plaintext.
 - List of cipher suites — "here are the crypto algorithms I support." We offered one: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 - SNI — the hostname we want, in plaintext. The server needs this to pick the right certificate (many sites share one IP).

 What an eavesdropper sees: Everything. The hostname, the random, the cipher list. That's fine — nothing secret here.

 ────────────────────────────────────────────────────────────────────────────────

 Step 2: ServerHello — "Agreed, let's use these settings"

 The server responds with:

 - Server random (32 bytes) — its own random number. Also not secret.
 - Chosen cipher suite — 0xC02F (it agreed to our proposal)
 - Session ID — for resuming this session later (optimization, not critical)

 What an eavesdropper sees: Everything. Still fine.

 At this point, both sides have agreed on which algorithms to use, but haven't exchanged any secret yet.

 ────────────────────────────────────────────────────────────────────────────────

 Step 3: Certificate — "Here's who I am"

 The server sends its certificate. This is a document that contains:

 - The server's RSA public key (modulus: 256 bytes, exponent: 65537)
 - The server's identity (hostname: *.azurewebsites.net)
 - A signature from a Certificate Authority (CA) that says "I verified this key belongs to this hostname"
 - Validity dates (not expired)

 What an eavesdropper sees: The certificate. That's public information — anyone can see it.

 What we do with it: Extract the RSA public key. We'll need it in the next step.

 What we should also do (but skip for now): Verify the CA's signature on the certificate, check the hostname matches, check it's not expired. This is the "chain of trust" — we trust the CA, the CA vouches for the server.

 ────────────────────────────────────────────────────────────────────────────────

 Step 4: ServerKeyExchange — "Here's my half of the secret exchange"

 This is where things get interesting. The server sends:

 Part A: The ECDH public key
 - A point on the P-256 elliptic curve (65 bytes)
 - This is the server's ephemeral (temporary) public key, generated fresh for this connection

 Part B: A signature over Part A
 - The server took: client_random + server_random + ECDH params from Part A
 - Hashed it all with SHA-256
 - Encrypted the hash with its RSA private key → that's the signature (256 bytes)

 Why Part B exists:

 Without the signature, an attacker could:
 1. Intercept the connection
 2. Replace the server's ECDH key with the attacker's own ECDH key
 3. We'd compute a shared secret with the attacker
 4. Attacker decrypts our traffic, re-encrypts to the real server
 5. We'd never know

 The signature prevents this. Only the real server can produce a valid signature because only it has the RSA private key. If anyone changes the ECDH key, the signature won't match.

 What we do:
 1. Rebuild the data: client_random + server_random + ECDH params
 2. Hash it: SHA-256 → 32 bytes
 3. "Decrypt" the signature with the RSA public key: signature^65537 mod n → reveals the original hash
 4. Compare our hash with the revealed hash
 5. If they match → the ECDH key is authentic, nobody tampered with it

 What an eavesdropper sees: The ECDH public key and the signature. They can see the public key but can't do anything useful with it alone — they'd need the server's ECDH private key (which was never sent).

 ────────────────────────────────────────────────────────────────────────────────

 Step 5: ServerHelloDone — "I'm done, your turn"

 An empty message. Just signals: "I've sent everything I need to send."

 ────────────────────────────────────────────────────────────────────────────────

 Step 6: ClientKeyExchange — "Here's my half of the secret exchange"

 Now it's our turn. We:

 1. Generate a random ECDH private key (32 bytes, never leaves our machine)
 2. Compute our ECDH public key: private_key × G (a point on P-256)
 3. Send our public key (65 bytes) to the server

 What an eavesdropper sees: Our ECDH public key. Again, useless without our private key.

 The magic: Now both sides can compute the same shared secret:

 ```
   We compute:     our_private × server_public_point = S
   Server computes: server_private × our_public_point = S  (same point!)
 ```

 This works because of how elliptic curve multiplication works:

 ```
   our_private × (server_private × G) = server_private × (our_private × G)
 ```

 The eavesdropper sees both public points but can't compute S without one of the private keys. This is the Elliptic Curve Diffie-Hellman problem — believed to be computationally impossible.

 Result: Both sides now have the same 32-byte premaster_secret (the X coordinate of point S). Nobody else knows it.

 ────────────────────────────────────────────────────────────────────────────────

 Step 7: Key Derivation — "Turn the shared secret into actual keys"

 The premaster_secret alone isn't used directly. We derive multiple keys from it:

 ```
   master_secret = PRF(premaster_secret, "master secret", client_random + server_random)
 ```

 The PRF (Pseudo-Random Function) stretches and mixes the premaster secret with both randoms. The randoms ensure that even if the same ECDH math produced the same premaster secret twice (unlikely), the keys would still differ.

 From the master secret, we derive:
 - Client write key (AES key for us to encrypt data we send)
 - Server write key (AES key for the server to encrypt data it sends)
 - Client write IV (initialization vector for our encryption)
 - Server write IV (initialization vector for server's encryption)

 Two separate keys because each direction is encrypted independently.

 ────────────────────────────────────────────────────────────────────────────────

 Step 8: ChangeCipherSpec + Finished — "I'm switching to encrypted mode"

 ChangeCipherSpec: A simple 1-byte message saying "everything after this is encrypted."

 Finished: The first encrypted message. It contains a hash of the entire handshake (all messages exchanged so far). Encrypted with the keys we just derived.

 Why: This proves:
 1. We successfully derived the keys (we can encrypt)
 2. Nobody tampered with any handshake message (the hash covers everything)

 The server sends its own ChangeCipherSpec + Finished (encrypted with its key). We decrypt it and verify the hash.

 If both Finished messages check out → handshake complete. From now on, all data is encrypted with AES-128-GCM.

 ────────────────────────────────────────────────────────────────────────────────