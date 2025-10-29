# Simple test client for VSCP WebSocket server (ws1 protocol)
# 
# Requires:
#   python -m venv .venv
#   source .venv/bin/activate
#   pip install websocket-client pycryptodome



import ssl
import time
import websocket
from Crypto.Cipher import AES

WS_URL = 'ws://localhost:8884/ws1'   # or wss://...
USERNAME = 'admin'
PASSWORD = 'secret'
# 16-byte shared key in hex (AES-128)
VSCP_KEY_HEX = '2DBB079A38985AF00EBEEFE22F9FFA0E'

def zero_pad(b: bytes, block=16) -> bytes:
    # Zero padding to 16-byte boundary (no extra block if already aligned)
    pad_len = (-len(b)) % block
    return b + (b'\x00' * pad_len)

def parse_msg(text: str):
    text = text.strip()
    parts = text.split(';')
    return {
        'raw': text,
        'type': parts[0] if parts else '',
        'cmd': parts[1] if len(parts) > 1 else '',
        'params': parts[2:] if len(parts) > 2 else []
    }

def recv_until_response(ws, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ws.settimeout(max(0.1, deadline - time.time()))
        data = ws.recv()
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='replace')
        msg = parse_msg(data)
        # Print events immediately
        if msg['type'] == 'E':
            print(f'Event: {msg["raw"]}')
            continue
        # Return on any response (+/-)
        if msg['type'] in ('+', '-'):
            return msg
        # Other lines (ignore/print)
        print(f'Recv: {msg["raw"]}')
    raise TimeoutError('Timed out waiting for response')

def send(ws, line: str):
    print(f'Send: {line}')
    ws.send(line)

def send_command(ws, command: str, timeout=5.0):
    full = command if command.startswith('C;') else f'C;{command}'
    send(ws, full)
    return recv_until_response(ws, timeout)

def send_event(ws, head, vscp_class, vscp_type, guid, data=None):
    if data is None:
        data = []
    # E;head,class,type,obid,datetime,timestamp,guid,data...
    # Keep datetime/timestamp simple for demo
    line = f'E;{head},{vscp_class},{vscp_type},0,0,0,{guid},{",".join(map(str, data))}'
    send(ws, line)

def main():
    sslopt = None
    if WS_URL.startswith('wss://'):
        # For self-signed testing, disable verification (NOT for production)
        sslopt = {"cert_reqs": ssl.CERT_NONE}

    ws = websocket.create_connection(WS_URL, timeout=5, sslopt=sslopt)
    print('Connected')

    # 1) Wait for AUTH0
    while True:
        data = ws.recv()
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='replace')
        msg = parse_msg(data)
        print(f'Recv: {msg["raw"]}')
        if msg['type'] == '+' and msg['cmd'] == 'AUTH0':
            sid = msg['params'][0]  # 16-byte IV in hex
            break

    # 2) Encrypt "username:password" with AES-128-CBC, ZeroPadding, IV = sid
    key = bytes.fromhex(VSCP_KEY_HEX)
    iv = bytes.fromhex(sid)
    creds = f'{USERNAME}:{PASSWORD}'.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(zero_pad(creds))
    ct_hex = ct.hex().upper()

    # 3) Send AUTH
    send(ws, f'C;AUTH;{sid};{ct_hex}')
    auth_resp = recv_until_response(ws, timeout=5)
    if not (auth_resp['type'] == '+' and auth_resp['cmd'] == 'AUTH1'):
        raise RuntimeError(f'Auth failed: {auth_resp}')

    print('Authenticated')

    # 4) Send some commands
    print('NOOP:', send_command(ws, 'NOOP'))
    print('VERSION:', send_command(ws, 'VERSION'))
    print('OPEN:', send_command(ws, 'OPEN'))

    # 5) Send a demo event
    send_event(
        ws,
        head=0,
        vscp_class=30,
        vscp_type=5,
        guid='FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00:00:02:00:00',
        data=[1, 2, 3, 4, 5, 6]
    )

    # 6) Read a few incoming frames (events/responses)
    try:
        for _ in range(5):
            msg = ws.recv()
            if isinstance(msg, bytes):
                msg = msg.decode('utf-8', errors='replace')
            print('Recv:', msg)
    except Exception as e:
        print('Read error:', e)

    # 7) Close channel and connection
    print('CLOSE:', send_command(ws, 'CLOSE'))
    ws.close()
    print('Closed')

if __name__ == '__main__':
    main()