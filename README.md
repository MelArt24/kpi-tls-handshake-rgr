# kpi-tls-handshake-rgr      
# Basic Version

# Steps of implementation:                           
Steps of implementation will be added to track the progress

## Phase 1
Phase 1 exchanges one UTF-8 plaintext line in each direction over TCP, then exits.                                        
No TLS or cryptography is implemented. Requires JDK 17.                                                                   
                                                                                                                         
### IntelliJ IDEA                                                                                                          
                                                                                                                         
1. Open as a Gradle project and sync with JDK 17.                                                                         
2. Run `main` using the gutter icon in `src/main/kotlin/ua/kpi/rgr/server/ServerMain.kt`.                                 
3. Wait for `[SERVER] Waiting for client...`.                                                                             
4. Run `main` in `src/main/kotlin/ua/kpi/rgr/client/ClientMain.kt` separately.                                            
                                                                                                                          
The server prints `Received: Hello from client`; the client prints                                                        
`Received: Hello from server`. Both close their connections and exit.                                                     
Restart the server before each exchange. Shared host/port: `common/NetworkConfig.kt`.                                     
                                                                                                                        
### Windows terminals                                                                                                      
                                                                                                                         
Build: `./gradlew.bat build`                                                                                              
                                                                                                                          
First terminal: `./gradlew.bat runServer`                                                                                 
                                                                                                                          
Second terminal: `./gradlew.bat runClient`                                                                                
                                                                                                                         
Starting the client without the server prints a clear connection error.  
## Phase 2
Phase 2 replaces the temporary raw plaintext strings with structured `ProtocolMessage` objects.
Each message has a `type` (`TEST_REQUEST` or `TEST_RESPONSE`) and a `payload` map of named textual fields.
Messages are serialized with kotlinx.serialization JSON and sent over ordinary unencrypted TCP.
No TLS or cryptography is implemented.

`protocol/MessageTransport.kt` handles JSON serialization, one UTF-8 line per message,
flushing, and deserialization. Newlines inside payload strings are escaped in JSON,
so each message occupies one physical line. The caller still owns and closes the socket.
Malformed messages, unexpected types, missing test message fields, and end-of-stream
produce clear errors.

### IntelliJ IDEA

The Phase 1 run instructions still apply: sync Gradle with JDK 17, run `ServerMain.kt`,
wait for `[SERVER] Waiting for client...`, then run `ClientMain.kt` separately.
Restart the server before each exchange.

### Windows terminals

Build and run the unit tests: `./gradlew.bat build`

Run tests separately: `./gradlew.bat test`

First terminal: `./gradlew.bat runServer`

Second terminal: `./gradlew.bat runClient`

During verification, the server prints the received `TEST_REQUEST` and `Hello from client`,
then sends `TEST_RESPONSE` with `Hello from server`. The client prints both the sent request
and received response, including their types and message fields. Both processes exit cleanly.
The shared address remains `localhost:8443` in `common/NetworkConfig.kt`.

Focused in-memory unit tests cover JSON round trips, UTF-8 text and spaces, escaped newlines,
separate message framing, malformed JSON, unknown types, and end-of-stream.

## Phase 3
Phase 3 replaces temporary `TEST_REQUEST` / `TEST_RESPONSE` with `CLIENT_HELLO` / `SERVER_HELLO`.
Client and server independently generate 32-byte random values using the JDK `SecureRandom`.
The JDK Base64 encoder converts these bytes to strings in the existing JSON payload map:
`CLIENT_HELLO` contains `clientRandom`; `SERVER_HELLO` contains `serverRandom`.

`crypto/CryptoRandom.kt` generates random bytes. `protocol/HelloRandomPayload.kt` validates
message types, required fields, Base64 encoding, and the exact 32-byte decoded length.
Both raw random values remain available as local byte arrays on each side during the exchange
for future session-key derivation; they are not persisted after the processes exit.
`MessageTransport` and its UTF-8 JSON line framing are unchanged.

Communication is still ordinary unencrypted TCP. The handshake is NOT complete,
and no certificate authentication or encryption exists yet.

### IntelliJ IDEA

Run `ServerMain.kt`, wait for `[SERVER] Waiting for client...`, then run `ClientMain.kt`
separately, using the same JDK 17 setup as previous phases.

### Windows terminals

Build and run all tests: `./gradlew.bat build`

Run tests separately: `./gradlew.bat test`

First terminal: `./gradlew.bat runServer`

Second terminal: `./gradlew.bat runClient`

Both consoles show `CLIENT_HELLO`, `SERVER_HELLO`, the Base64 random values, their 32-byte
lengths, and `Hello exchange completed.` before exiting. Restart the server and client
for another exchange: each run should show different random values. The address remains
`localhost:8443`. The full TLS handshake is not completed by this exchange.

Tests retain the Phase 2 transport coverage with the new message types and add random-size,
independent-generation, Base64 round-trip, valid-payload, malformed-Base64, wrong-length,
missing-field, and unexpected-type checks.

## Phase 4
Phase 4 adds an offline local educational PKI generator. It creates an RSA-2048 Root CA
key pair and a separate RSA-2048 server key pair using JCA and secure randomness.
Bouncy Castle constructs real X.509 certificates; both are signed with `SHA256withRSA`.

The self-signed Root CA has subject `CN=RGR Root CA`, a five-year validity period,
critical CA BasicConstraints, and `keyCertSign` / `cRLSign` key usages.
The one-year server certificate has subject `CN=localhost`, issuer `CN=RGR Root CA`,
and the server public key. It includes non-CA BasicConstraints, `digitalSignature` /
`keyEncipherment` usages, `serverAuth` extended usage, and SAN entries `DNS:localhost`
and `IP:127.0.0.1`. Both certificates have positive random serial numbers.

The Root CA private key is used only in memory to issue the certificates and is not saved.
The server private key is stored in a password-protected PKCS#12 keystore with alias `server`
and the ordered server/Root CA certificate chain. The fixed password `rgr-local-only`
is for local educational use only and is not suitable for production credentials.
No private key is included in either certificate file or printed to the console.

### IntelliJ IDEA

Run `main` in `certificate/CertificateGeneratorMain.kt` with the working directory set
to the project root, or run the `generateCertificates` Gradle task.
The existing server/client run instructions remain unchanged.

### Windows terminals

Build and run all tests: `./gradlew.bat build`

Generate local credentials: `./gradlew.bat generateCertificates`

The command creates the project-root `certificates/` directory and writes:

- `certificates/root-ca.crt`: PEM X.509 Root CA certificate.
- `certificates/server.crt`: PEM X.509 server certificate signed by the Root CA.
- `certificates/server-keystore.p12`: server private key and certificate chain.

Running generation again replaces these three files with a fresh CA and server identity.
The entire generated directory is gitignored. Do not commit generated credentials.
The Root CA is not installed in Windows or any other system-wide trust store.

Generation checks validity, verifies both signatures, verifies CA flags, issuer, and
server public key, then saves the files. It reloads both PEM files using the JVM X.509
CertificateFactory and checks the saved PKCS#12 private key and chain before reporting success.
The console shows subjects, issuer, signature algorithms, SAN entries, validity, and output paths.
Tests generate material in memory and temporary directories rather than using local credentials.

Certificates are NOT yet transmitted or validated during the live handshake.
`runServer` / `runClient` still exchange only `CLIENT_HELLO` / `SERVER_HELLO` and their
32-byte random values. The connection remains unencrypted ordinary TCP; the handshake
is incomplete. No premaster secret, key exchange, session keys, or encrypted data are added.

## Phase 5
`SERVER_HELLO` now contains both `serverRandom` and `serverCertificate`. The server loads
`certificates/server.crt` and transfers its X.509 DER bytes as a Base64 string inside the
existing JSON payload. `ProtocolMessage`, UTF-8 line framing, and the raw random byte arrays
are preserved. The Root CA is NOT sent by the server as a trusted object.

The client requires and decodes the certificate payload with JDK Base64 and parses X.509
using the JVM CertificateFactory. It independently loads `certificates/root-ca.crt`.
The trusted root must be currently valid, marked as a CA, self-issued, and self-signed.
The client uses JVM PKIX CertPathValidator with the server certificate as the path and the
local root as a TrustAnchor. An unrelated Root CA rejects the server even if its subject
and issuer names look correct.

Revocation checking is disabled because this educational CA has no CRL or OCSP infrastructure;
revocation is outside the current base variant and is not checked.
After PKIX validation, the client requires a non-CA RSA certificate, keyEncipherment key usage,
and serverAuth EKU. It verifies an exact DNS SAN for `localhost`, or an exact IP SAN for an
IP host such as `127.0.0.1`. There is no CN fallback or wildcard hostname matching.
Missing fields, malformed Base64/X.509, missing files, and failed authentication stop processing.

### IntelliJ IDEA

Generate certificates first, then run `ServerMain.kt` and `ClientMain.kt` separately as before.
Keep the working directory set to the project root so both use the same local certificate set.
Credentials are never generated automatically at application startup.

### Windows terminals

Build and run all tests: `./gradlew.bat build`

Prerequisite: `./gradlew.bat generateCertificates`

First terminal: `./gradlew.bat runServer`

Second terminal: `./gradlew.bat runClient`

The server logs the certificate subject and issuer attached to SERVER_HELLO. The client logs
received certificate metadata, successful PKIX/usage/SAN checks, and `SERVER AUTHENTICATED`.
Both processes then close cleanly. Missing certificate errors tell you to run generateCertificates.
The generated directory remains gitignored and no system trust store is changed.

Tests cover certificate payload round trips and malformed/missing data, local PEM loading,
matching and unrelated Root CA trust, localhost/IP SAN verification, wrong host rejection,
CA/usage/EKU rejection, absent SAN without CN fallback, and expired-certificate rejection.
All earlier tests are retained.

The connection is still unencrypted ordinary TCP and the handshake is still incomplete.
Certificates are validated, but proof of possession of the server private key belongs to later
phases. No premaster secret, RSA encryption/decryption, session-key derivation, AES, or finished
messages are implemented.

## Phase 6
Phase 6 adds `CLIENT_KEY_EXCHANGE`. After the received X.509 server certificate passes
PKIX, SAN, and usage validation, the client generates a fresh 48-byte premaster secret
using SecureRandom. Encryption uses the public key from that same authenticated certificate.
This follows the assignment's simplified historical RSA premaster exchange model.

`crypto/RsaKeyExchange.kt` uses RSA-OAEP with SHA-256 and explicitly specifies SHA-256,
MGF1-SHA256, and the empty default label for both encryption and decryption. Only the RSA
ciphertext travels over TCP, Base64-encoded in the JSON `encryptedPremaster` payload field.
The raw premaster is never transmitted or logged. No fingerprint is sent in the protocol.

Before accepting a client, `certificate/ServerCredentialsLoader.kt` loads the PKCS#12 private
key using the existing `server` alias and local educational password. It requires an RSA
private-key entry and X.509 chain, compares the leaf DER with `server.crt`, and checks that
the private key's RSA modulus matches the certificate public key. Missing or mismatched
credentials stop startup; run generateCertificates to create a consistent set.
The server sends this checked certificate, waits for CLIENT_KEY_EXCHANGE, and decrypts
with the matching private key. Wrong types, missing fields, invalid Base64, empty or invalid
ciphertext, failed OAEP decryption, and a recovered length other than 48 bytes are rejected.

Both processes keep raw `clientRandom`, `serverRandom`, and `premasterSecret` byte arrays
locally during the exchange for the next phase. After decryption, both consoles display a
local SHA-256 premaster fingerprint so matching secrets can be demonstrated without printing
the raw secret. These fingerprints are educational diagnostics only.

### IntelliJ IDEA

Generate certificates first, then run ServerMain and ClientMain separately as before.
Keep the project root as the working directory. Credentials are not regenerated at startup.

### Windows terminals

Build and run all tests: `./gradlew.bat build`

Prerequisite: `./gradlew.bat generateCertificates`

First terminal: `./gradlew.bat runServer`

Second terminal: `./gradlew.bat runClient`

Verify SERVER AUTHENTICATED appears before the client key exchange. The client generates
48 premaster bytes and sends a 256-byte RSA-2048 ciphertext. The server recovers 48 bytes.
The two Premaster SHA-256 values must match, and both processes terminate cleanly.
No new server acknowledgement message is added.

Tests cover fresh premaster generation, explicit OAEP interoperability, exact byte recovery,
wrong keys, corrupted ciphertext, incompatible keys and OAEP parameters, length validation,
payload round trips and rejection, and temporary PKCS#12 loading/mismatch checks.
An in-memory test validates the certificate before encrypting for the loaded server private key.
All Phase 1-5 tests are retained. Generated credentials remain gitignored.

Session keys are NOT derived yet. Traffic is not symmetrically encrypted: the hello messages
remain readable JSON and only the premaster value is RSA-encrypted. The full handshake is
still incomplete. No master secret, HKDF, AES, finished messages, or application data is added.

## Phase 7
Client and server now independently derive two directional session keys after the RSA
premaster exchange. The inputs are the locally retained 48-byte premaster secret,
32-byte clientRandom, and 32-byte serverRandom. Invalid input lengths are rejected.

`crypto/HkdfSha256.kt` implements RFC 5869 Extract-and-Expand with JDK HmacSHA256,
Mac, and SecretKeySpec, without additional dependencies. Expansion supports zero output
bytes and rejects negative lengths or lengths exceeding 255 * 32 = 8160 bytes.

The project's educational KDF design is explicit:

- IKM: premasterSecret.
- Salt: clientRandom || serverRandom, in that order (64 bytes).
- Info: `kpi-rgr-tls-session-keys-v1`, encoded as UTF-8.
- Output: 64 bytes.
- First 32 bytes: clientWriteKey for future client-to-server traffic.
- Next 32 bytes: serverWriteKey for future server-to-client traffic.

`crypto/SessionKeyDerivation.kt` returns SessionKeys containing the two raw 32-byte arrays,
retained locally on each side for the next phase. This is the specified project KDF, not
an implementation of the complete TLS 1.2 PRF or a migration to TLS 1.3.

Session keys are NEVER sent over TCP and raw keys are never logged. The generic
CryptoFingerprint helper preserves the existing uppercase SHA-256 diagnostic format for
premaster and key fingerprints. Each process prints its local clientWriteKey and serverWriteKey
fingerprints: corresponding directions must match between processes, while the two directions
differ. No protocol message types or payload fields were added.

### IntelliJ IDEA

Run ServerMain and ClientMain separately with the project root as working directory,
after generating certificates as in previous phases.

### Windows terminals

Build and run all tests: `./gradlew.bat build`

Prerequisite: `./gradlew.bat generateCertificates`

First terminal: `./gradlew.bat runServer`

Second terminal: `./gradlew.bat runClient`

Verify SERVER AUTHENTICATED, the premaster exchange, and `[5] SESSION KEY DERIVATION`.
Both processes report two 32-byte keys and Session key derivation completed, then exit.
Compare clientWriteKey SHA-256 client/server values and serverWriteKey SHA-256 client/server
values independently. Generated credentials remain gitignored.

Tests include published RFC 5869 SHA-256 PRK/OKM vectors (Appendices A.1 and A.3),
multiple-block expansion, empty output, maximum/negative lengths, deterministic directional
key equality, input sensitivity and ordering, and invalid input sizes. Key tests compare
actual byte contents rather than only fingerprints. All earlier test coverage is preserved.

AES encryption, IVs/nonces, READY/finished messages, and application data are NOT implemented.
Traffic is not symmetrically encrypted, and the full handshake remains incomplete.

## Phase 8
Phase 8 introduces AES-256-GCM encrypted readiness confirmations after session-key derivation.
The JDK AES/GCM/NoPadding cipher uses 32-byte keys, a fresh SecureRandom 12-byte IV for every
encryption, and a 128-bit authentication tag. The ciphertext returned by doFinal includes the
encrypted plaintext followed by the tag; there is no separate tag field.

CLIENT_FINISHED carries encrypted UTF-8 CLIENT_READY protected by clientWriteKey.
After authenticating and verifying that exact value, the server sends SERVER_FINISHED carrying
encrypted SERVER_READY protected by serverWriteKey. Both use the existing JSON line transport,
with only Base64 `iv` and `ciphertext` payload fields. READY plaintext is never sent in JSON.
The UTF-8 protocol type name (CLIENT_FINISHED or SERVER_FINISHED) is AES-GCM AAD, binding the
visible envelope type to its encrypted contents.

Wrong keys, modified ciphertext/tag/IV, incorrect AAD, wrong READY values, and malformed
payloads abort the handshake. No unauthenticated plaintext is returned and no plaintext fallback
or alternate-key retry exists. Raw session keys remain local and are never transmitted or logged.
Directional key fingerprints from Phase 7 remain local educational diagnostics.

### IntelliJ IDEA

Generate certificates first, then run ServerMain and ClientMain separately with the project
root as working directory, as in previous phases.

### Windows terminals

Build and run all tests: `./gradlew.bat build`

Prerequisite: `./gradlew.bat generateCertificates`

First terminal: `./gradlew.bat runServer`

Second terminal: `./gradlew.bat runClient`

After authentication, premaster exchange, and key derivation, both consoles show
`[6] ENCRYPTED HANDSHAKE CONFIRMATION`. The server verifies CLIENT_READY before sending
SERVER_FINISHED. The client verifies SERVER_READY before reporting EDUCATIONAL TLS-LIKE
HANDSHAKE COMPLETED and SECURE SESSION ESTABLISHED. Both processes then close cleanly.
The server reports its confirmation sent; there is no additional client acknowledgement.

This is an educational TLS-like simulation, not standards-compliant real TLS. The two Finished
messages are encrypted READY confirmations, not real TLS transcript-bound Finished verify_data.
The handshake is considered complete after both READY confirmations succeed. The client can
observe completion after verifying the server's response; the server does not receive a further
acknowledgement proving client receipt. No transcript hashes or new acknowledgement are added.

Tests cover AES-GCM byte/UTF-8 round trips, IV size/freshness, wrong keys, ciphertext/tag/IV/AAD
tampering, invalid lengths, Finished JSON framing and payload validation, exact READY validation,
message-type binding, and directional keys derived independently from the same Phase 7 inputs.
All prior tests remain. Generated certificate material stays gitignored.

Protected application-data transfer, chat, file transfer, and interactive loops are NOT implemented.
No APPLICATION_DATA type or real SSL/TLS sockets are added. Only the READY confirmations are
AES-GCM encrypted in this phase; earlier handshake messages retain their existing representation.

## Phase 9
Protected application-data transfer now provides a simple alternating two-way console chat.
APPLICATION_DATA was added. One TCP connection performs the educational TLS-like handshake
once, then reuses its already derived directional session keys for multiple encrypted messages.
The client starts chat only after validating SERVER_FINISHED. The server starts receiving chat
only after validating CLIENT_FINISHED and sending SERVER_FINISHED.

Client-to-server messages use clientWriteKey and UTF-8 AAD `APPLICATION_DATA:CLIENT_TO_SERVER`.
Server-to-client replies use serverWriteKey and UTF-8 AAD `APPLICATION_DATA:SERVER_TO_CLIENT`.
These constants and key selections are shared in SecureApplicationData. The existing AES-256-GCM
utility gives every message a fresh random 12-byte IV and a 128-bit authentication tag.
ApplicationDataPayload preserves the one-JSON-object-per-UTF-8-line transport and contains only
Base64 `iv` and `ciphertext` fields; ciphertext includes the GCM tag. Plaintext is never put into
protocol JSON. Received chat text is displayed only after authenticated decryption.

Chat text uses UTF-8, including Ukrainian text such as `Привіт! Як справи?`. The client sends
one message, the server displays it and prompts for one reply, and the client displays that reply
before prompting again. There are no concurrent console threads or additional handshakes.
Wrong keys, wrong directional AAD, tampering, and malformed payloads abort processing.

### IntelliJ IDEA

Run ServerMain and ClientMain separately after generating credentials, with the project root
as working directory. Use UTF-8 console input/output. Wait for secure chat to start, then type
in the client console first; reply in the server console when prompted.

### Windows terminals

Build and run all tests: `./gradlew.bat build`

Prerequisite: `./gradlew.bat generateCertificates`

First terminal: `./gradlew.bat runServer --console=plain`

Second terminal: `./gradlew.bat runClient --console=plain`

The Gradle tasks now forward standard input to each application. Use UTF-8 terminals for
Ukrainian text. After handshake completion, the client shows `[CLIENT] You:`. The server displays
`[SERVER] Client: ...` and prompts `[SERVER] You:`; the client displays `[CLIENT] Server: ...`.
Exchange several messages without restarting either process.

Enter `/exit` on either side's turn to stop. It is encrypted as APPLICATION_DATA using the same
keys and direction-specific AAD, never as a plaintext control command. The sender closes after
sending it and the receiver closes after decrypting it. Console end-of-input also sends encrypted
`/exit`. Unexpected network closure remains a clear network/protocol error.

Tests cover encrypted JSON round trips with only IV/ciphertext, malformed fields and incomplete
tags, exact Ukrainian/UTF-8 and long multiline recovery, independent IVs, wrong keys, opposite
AAD even with an identical key, ciphertext/tag/IV tampering, encrypted exit, and repeated requests
and replies using independently handshake-derived keys. All earlier tests are retained.
Raw keys/premaster are not printed. Generated credentials remain gitignored.

There is no packet-size limit, fragmentation/reassembly, multiple-node abstraction, routing,
or Double Star topology yet. This remains an educational simulation, not standards-compliant TLS.
