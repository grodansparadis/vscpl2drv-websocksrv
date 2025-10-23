# Test code for the Websocket interface

This folder contains files for websocket tests

## mintest_ws1.html
Simplest possible login test for VSCP ws1 websocket interface.

## test_ws1.py
Python (ver 3) code to login on the websocket interface and perform
some VSCP ws1 websocket commands and then wait for incoming events. User, password and key should be set to default values.

## test_ws2.py
Python (ver 3) code to login on the websocket interface and perform
some VSCP ws2 websocket commands and then wait for incoming events. User, password and key should be set to default values.

## test_ws1.js
node.js code to login on the websocket interface and perform
some VSCP ws1 websocket commands and then wait for incoming events. User, password and key should be set to default values.

## test_ws2.js
node.js code to login on the websocket interface and perform
some VSCP ws2 websocket commands and then wait for incoming events. User, password and key should be set to default values.


## Requirements

* Python 3 with `websockets` and `cryptography` packages installed
* node.js with `ws` and `crypto` packages installed
* A running VSCP daemon with websocket interface enabled
* A web browser for the HTML test
* Basic knowledge of VSCP and websockets
  
### Python

```bash
python -m venv .venv
source .venv/bin/activate
pip install websockets
pip install cryptography
``` 

### node.js

```bash
npm install ws
```
