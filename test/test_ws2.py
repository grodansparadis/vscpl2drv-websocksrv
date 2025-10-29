#!/usr/bin/env python3
"""
VSCP WS2 Protocol Client
Demonstrates JSON-based WebSocket communication with VSCP server
"""

import ssl
import time
import json
import websocket
from Crypto.Cipher import AES
from datetime import datetime

WS_URL = 'ws://localhost:8884/ws2'   # or wss://...
USERNAME = 'admin'
PASSWORD = 'secret'
# 16-byte shared key in hex (AES-128)
VSCP_KEY_HEX = '2DBB079A38985AF00EBEEFE22F9FFA0E'

def zero_pad(b: bytes, block=16) -> bytes:
    """Zero padding to 16-byte boundary (no extra block if already aligned)"""
    pad_len = (-len(b)) % block
    return b + (b'\x00' * pad_len)

def parse_msg(text: str):
    """Parse JSON message"""
    try:
        return json.loads(text.strip())
    except json.JSONDecodeError as e:
        print(f'JSON parse error: {e}')
        return {'type': 'UNKNOWN', 'raw': text}

def recv_until_response(ws, command=None, timeout=10.0):
    """Receive messages until we get a response for our command"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        ws.settimeout(max(0.1, deadline - time.time()))
        data = ws.recv()
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='replace')
        
        msg = parse_msg(data)
        
        # Print events immediately
        if msg.get('type') == 'E':
            print(f'Event: {json.dumps(msg, indent=2)}')
            continue
        
        # Return on any response (+/-) matching our command (or any if command is None)
        if msg.get('type') in ('+', '-'):
            if command is None or msg.get('command') == command:
                return msg
        
        # Other messages
        print(f'Recv: {json.dumps(msg, indent=2)}')
    
    raise TimeoutError(f'Timed out waiting for response to: {command}')

def send_json(ws, obj: dict):
    """Send JSON object"""
    json_str = json.dumps(obj)
    print(f'Send: {json_str}')
    ws.send(json_str)

def send_command(ws, command: str, args=None, timeout=5.0):
    """Send command and wait for response"""
    if args is None:
        args = {}
    
    cmd = {
        'type': 'CMD',
        'command': command,
        'args': args
    }
    
    send_json(ws, cmd)
    return recv_until_response(ws, command, timeout)

def send_event(ws, vscp_class: int, vscp_type: int, guid: str, data=None, note=''):
    """Send VSCP event"""
    if data is None:
        data = []
    
    event = {
        'type': 'E',
        'event': {
            'head': 0,
            'vscpClass': vscp_class,
            'vscpType': vscp_type,
            'obid': 0,
            'dateTime': datetime.utcnow().isoformat() + 'Z',
            'timestamp': 0,
            'guid': guid,
            'data': data,
            'note': note
        }
    }
    
    send_json(ws, event)

def encrypt_auth(iv_hex: str, key_hex: str, username: str, password: str) -> str:
    """Encrypt username:password with AES-128-CBC using zero padding"""
    key = bytes.fromhex(key_hex)
    iv = bytes.fromhex(iv_hex)
    creds = f'{username}:{password}'.encode('utf-8')
    
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(zero_pad(creds))
    return ct.hex().upper()

def main():
    sslopt = None
    if WS_URL.startswith('wss://'):
        # For self-signed testing, disable verification (NOT for production)
        sslopt = {"cert_reqs": ssl.CERT_NONE}

    print(f'Connecting to {WS_URL}...')
    ws = websocket.create_connection(WS_URL, timeout=5, sslopt=sslopt)
    print('Connected to WS2 server')

    # 1) Wait for AUTH0
    print('Waiting for AUTH0...')
    while True:
        data = ws.recv()
        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='replace')
        
        msg = parse_msg(data)
        print(f'Recv: {json.dumps(msg, indent=2)}')
        
        # WS2 sends: {"type":"+","command":"AUTH","args":["AUTH0","sid-in-hex"]}
        if (msg.get('type') == '+' and 
            isinstance(msg.get('args'), list) and 
            len(msg['args']) >= 2 and 
            msg['args'][0] == 'AUTH0'):
            sid = msg['args'][1]
            print(f'Received AUTH0, SID: {sid}')
            break

    # 2) Encrypt "username:password" with AES-128-CBC, ZeroPadding, IV = sid
    print('Encrypting credentials...')
    ct_hex = encrypt_auth(sid, VSCP_KEY_HEX, USERNAME, PASSWORD)

    # 3) Send AUTH command
    auth_cmd = {
        'type': 'CMD',
        'command': 'AUTH',
        'args': {
            'iv': sid,
            'crypto': ct_hex
        }
    }
    send_json(ws, auth_cmd)
    
    # Wait for AUTH response
    auth_resp = recv_until_response(ws, 'AUTH', timeout=5)
    if auth_resp.get('type') != '+':
        raise RuntimeError(f'Auth failed: {auth_resp}')
    
    print('✓ Authenticated successfully')

    # 4) Send some WS2 commands
    print('\n=== Sending commands ===')
    
    print('\nNOOP:')
    resp = send_command(ws, 'NOOP')
    print(f'Response: {json.dumps(resp, indent=2)}')
    
    time.sleep(0.5)
    
    print('\nVERSION:')
    resp = send_command(ws, 'VERSION')
    print(f'Response: {json.dumps(resp, indent=2)}')
    
    time.sleep(0.5)
    
    print('\nCOPYRIGHT:')
    resp = send_command(ws, 'COPYRIGHT')
    print(f'Response: {json.dumps(resp, indent=2)}')
    
    time.sleep(0.5)
    
    print('\nOPEN:')
    resp = send_command(ws, 'OPEN')
    print(f'Response: {json.dumps(resp, indent=2)}')
    
    time.sleep(0.5)

    # 5) Send a demo event
    print('\n=== Sending event ===')
    send_event(
        ws,
        vscp_class=30,
        vscp_type=5,
        guid='FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00:00:02:00:00',
        data=[1, 2, 3, 4, 5, 6],
        note='Test event from WS2 Python client'
    )
    print('Event sent')
    
    time.sleep(0.5)

    # 6) Read a few incoming frames (events/responses)
    print('\n=== Listening for events (5 seconds) ===')
    try:
        ws.settimeout(5.0)
        for _ in range(10):
            msg = ws.recv()
            if isinstance(msg, bytes):
                msg = msg.decode('utf-8', errors='replace')
            parsed = parse_msg(msg)
            print(f'Recv: {json.dumps(parsed, indent=2)}')
    except websocket.WebSocketTimeoutException:
        print('No more messages (timeout)')
    except Exception as e:
        print(f'Read error: {e}')

    # 7) Close channel and connection
    print('\n=== Closing ===')
    resp = send_command(ws, 'CLOSE')
    print(f'CLOSE response: {json.dumps(resp, indent=2)}')
    
    ws.close()
    print('✓ Connection closed')

if __name__ == '__main__':
    main()