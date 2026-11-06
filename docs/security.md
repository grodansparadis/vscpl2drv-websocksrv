# Security considerations

The WebSocket driver provides user authentication and optional TLS. Configure
both appropriately before making the listener accessible to other computers.

## Protect connections with TLS

Use `wss://` whenever traffic can cross an untrusted network. With `ws://`,
network observers can read the connection, including authentication traffic
and VSCP events. Configure the listener's `interface` with the `wss://` scheme
and provide the server certificate and private key in the `tls` section. See
[TLS configuration](./configure.md#tlsssl) and the
[self-signed certificate guide](./self_signed_server_certificates.md).

Use a certificate trusted by clients and matching the server hostname.
Self-signed certificates are suitable for isolated testing only; install and
trust the certificate explicitly on test clients rather than disabling
certificate validation.

The VSCP authentication exchange encrypts credentials using the configured
shared key, but that mechanism is not a replacement for TLS. Use TLS to protect
the entire connection and authenticate the server.

## Protect keys and user data

- Store the user JSON file and the key referenced by `key-file` in
  administrator-controlled locations. Restrict read permissions to the
  account running the driver and any authorized client-side provisioning
  process.
- The `key-file` is a shared VSCP authentication key, not the TLS private key.
  Generate a unique key for each deployment, share it only with authorized
  clients, and replace it if it may have been exposed.
- Store user passwords as Argon2id hashes, never plaintext. The `password`
  fields in the user database must contain hashes accepted by libsodium's
  Argon2id verification function. See the
  [user file format](./configure.md#user-file-format).
- Do not deploy the sample accounts or sample keys. Replace sample credentials,
  hashes, keys, and certificate paths before exposing a server.

## Password memory protection

The server uses libsodium's guarded allocations for decrypted login credentials
and in-memory Argon2id hashes. It explicitly checks `sodium_mlock`: allocation
or locking failure rejects the operation rather than falling back to ordinary,
swappable memory. Libsodium guards allocations against overruns and excludes
them from core dumps where the operating system supports that facility.

Decryption writes directly into locked memory. The password is passed to the
Argon2id verifier as a non-owning view, not copied into an ordinary
`std::string`. The buffer is wiped and released when authentication finishes,
including on rejected logins and exceptions. Password whitespace and colons
are preserved.

Hashes loaded from the user JSON file use locked input buffers and secure
JSON string allocations. The file is read without ordinary stdio buffering.
Account hashes remain in guarded, locked memory until replacement or account
destruction; released allocations are wiped by `sodium_free`. User-setting
responses contain asterisks rather than password hashes. The on-disk file must
still contain Argon2id hashes, not plaintext passwords.

Memory locking is limited by the host. On Linux, check the service's
`LimitMEMLOCK` or the launching shell's `ulimit -l` if loading users or logging
in fails with an inability to lock memory. Allow enough locked memory for the
user file, JSON parsing, resident hashes, and concurrent login buffers; guarded
allocations use page-granular mappings. Increase the service's limit as needed
rather than running it as root or disabling the lock checks.

These protections apply to the server's credential storage, not to all memory
in the host process, cryptographic-library internals, CPU registers, kernel
buffers, or a privileged debugger. Callers supplying passwords or hashes
through the C++ user-list APIs must protect their own input storage. A returned
hash view borrows the account's storage and must not outlive the account or a
hash replacement.

The Python, JavaScript, browser, and sample C clients are demonstration tools
and do not guarantee locked, wipeable credential storage. Python and JavaScript
strings can leave runtime-managed copies that cannot reliably be erased;
environment variables, browser fields, and source literals also retain values.
Do not treat their sample password settings as a production secret store. Use
TLS regardless of memory protection.

## Limit network and account access

- Bind to loopback (`localhost` or `127.0.0.1`) when only local clients need
  access. When remote access is required, restrict reachability with the host
  firewall and network controls.
- Configure each user's remote-address restrictions, rights, allowed events,
  and filters to the minimum required. Do not grant administrator rights to
  clients that do not need them.
- Keep the user file, configuration, TLS private key, and logs out of
  web-accessible directories. Use restrictive file and directory permissions.
- Run the VSCP host and driver with only the operating-system permissions they
  need; do not run the daemon as an administrator/root solely to make files
  writable.

## Deployment checklist

Before enabling remote connections, verify that:

1. The listener uses `wss://` and clients validate the server certificate.
2. The shared VSCP key and TLS private key are protected and are not reused as
   each other.
3. Every account has a non-plaintext Argon2id password hash and only the
   required rights.
4. Sample accounts and development credentials have been removed or changed.
5. The listener is reachable only from intended client networks.
