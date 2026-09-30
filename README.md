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
