# kpi-tls-handshake-rgr                                                                                                   

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
