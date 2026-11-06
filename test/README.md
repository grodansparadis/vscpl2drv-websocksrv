# Test code for the Websocket interface

This folder contains files for websocket tests

## Secure-memory test

The main build includes a CTest test for password verification, locked hash
storage, masked user responses, and secure-memory failure handling:

```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --target test-securememory --parallel
ctest --test-dir build -R secure-password-memory --output-on-failure
```

On Linux it also checks the actual memory mappings for lock and no-core-dump
flags and verifies that an allocation fails when the locked-memory limit is
zero. The operating system must permit the normal test allocations to be
locked.

## Authentication regression test

From the repository root, build both targets and run with Node.js 22 or later:

```bash
cmake --build build --target vscpl2drv-websocksrv testapp --parallel
node test/test_auth.mjs ./build/testapp/bin/testapp ./build/libvscpl2drv-websocksrv.so
```

Adjust the executable and shared-library paths for your platform. The test
starts its own local servers on temporary ports, checks WS1 and WS2 login with
the default key and key files, covers exact-block and multi-block credentials,
and verifies rejection of invalid credentials, malformed authentication data,
and invalid key files. It does not require additional Node.js packages or
interrupt an existing test server.

## Sample clients

Start the [test server](../docs/using.md#running-the-test-app-as-a-ws1ws2-server)
in a separate terminal first. A VSCP daemon is not required when using
`testapp`. Run all commands below from the repository root.

Each client authenticates, sends commands, opens its receive channel, sends a
class 30/type 5 event, and displays incoming events. Python and JavaScript
clients close the channel and exit after a short demonstration. C clients run
until Ctrl-C unless `VSCP_TEST_SECONDS` is set. Failures return a nonzero exit
status.

### Python clients

Requires Python 3.9 or later, `websocket-client`, and `pycryptodome`. These are
not the similarly named `websockets` and `cryptography` packages.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install websocket-client pycryptodome
python test/test_ws1.py
python test/test_ws2.py
```

On Windows, activate the environment with `.venv\Scripts\Activate.ps1`.

### JavaScript clients

Requires Node.js and the `ws` package. The `node:crypto` module is built into
Node.js and does not need to be installed.

```bash
npm install --prefix test --no-save ws
node test/test_ws1.js
node test/test_ws2.js
```

### C clients

Requires a C compiler, CMake, OpenSSL development libraries, and threading
support. The clients use the Mongoose sources included in this folder.
The client build is independent of the main driver build:

```bash
cmake -S test -B build/clients
cmake --build build/clients --parallel
./build/clients/test_ws1
./build/clients/test_ws2
```

For Visual Studio, supply the vcpkg toolchain and `-A x64` when configuring,
build with `--config Release`, and run the executables from
`build/clients/Release`.

These C samples support `ws://` only and explicitly reject `wss://`; use the
Python or JavaScript clients for TLS. Press Ctrl-C for a graceful close, or run
a bounded test:

```bash
VSCP_TEST_SECONDS=7 ./build/clients/test_ws1
VSCP_TEST_SECONDS=7 ./build/clients/test_ws2
```

In bounded mode, the C clients fail if authentication, event transmission, or
event reception did not complete before shutdown.

### Connection settings

All six clients accept the same environment variables:

| Variable | Default |
| -------- | ------- |
| `VSCP_WS_URL` | `ws://localhost:8884/ws1` or `ws://localhost:8884/ws2`, matching the client |
| `VSCP_USERNAME` | `admin` |
| `VSCP_PASSWORD` | `secret` |
| `VSCP_KEY_HEX` | `2DBB079A38985AF00EBEEFE22F9FFA0E` (16-byte AES key as hex) |

For example:

```bash
VSCP_WS_URL=ws://127.0.0.1:8884/ws1 python test/test_ws1.py
VSCP_WS_URL=ws://127.0.0.1:8884/ws2 node test/test_ws2.js
```

In PowerShell, set variables before running a client:

```powershell
$env:VSCP_WS_URL = "ws://127.0.0.1:8884/ws2"
node test/test_ws2.js
```

The default credentials and key are for local testing only. For a custom
`key-file`, set `VSCP_KEY_HEX` to its first 32 hexadecimal characters. Python
and JavaScript clients verify TLS certificates when using `wss://`. Install
your issuing CA in the client's trust store rather than disabling verification;
Node.js also supports `NODE_EXTRA_CA_CERTS`.

### Cross-language regression test

After installing the Python and JavaScript dependencies and building the
driver, test app, and C clients, run with Node.js 22 or later:

```bash
node test/test_clients.mjs \
  ./build/testapp/bin/testapp \
  ./build/libvscpl2drv-websocksrv.so \
  ./build/clients/test_ws1 \
  ./build/clients/test_ws2
```

Set `PYTHON` to your virtual environment's Python executable if it is not
already active. Adjust executable and library paths for your platform.
The test starts an isolated local server and runs all six clients concurrently.
It checks authentication, commands, sending and receiving events, and shutdown
with normal, exact-block, multi-block, and UTF-8 credentials. It also verifies
that every client exits unsuccessfully for an incorrect password or AES key.
