const WebSocket = require('ws');
const {
  createCipheriv,
} = require('node:crypto');

// Configuration
const WS_URL = process.env.VSCP_WS_URL || 'ws://localhost:8884/ws2';
const algorithm = 'aes-128-cbc';
const key = Buffer.from(process.env.VSCP_KEY_HEX || '2DBB079A38985AF00EBEEFE22F9FFA0E', 'hex');
const username = process.env.VSCP_USERNAME || 'admin';
const password = process.env.VSCP_PASSWORD || 'secret';

class VSCPWebSocketClient_WS2 {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.authenticated = false;
    this.sessionId = null;
    this.isOpen = false;
    this.authResolver = null;
    this.messageId = 1;
  }

  /**
   * Connect to WebSocket server
   */
  async connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url, {
        perMessageDeflate: false
      });

      this.ws.on('open', () => {
        console.log('✓ Connected to WebSocket server (WS2)');
        this.isOpen = true;
      });

      this.ws.on('message', (data) => {
        try {
          this.handleMessage(data);
        } catch (error) {
          console.error('Message handling failed:', error.message);
          process.exitCode = 1;
          this.ws.close();
          reject(error);
        }
      });

      this.ws.on('error', (error) => {
        console.error('❌ WebSocket error:', error);
        reject(error);
      });

      this.ws.on('close', () => {
        console.log('❌ Connection closed');
        this.isOpen = false;
      });

      // Resolve only after the server accepts authentication.
      this.waitForAuth().then(resolve).catch(reject);
    });
  }

  /**
   * Answer AUTH0 and wait for authentication success or rejection
   */
  waitForAuth() {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.authResolver = null;
        reject(new Error('Authentication timeout - no AUTH response received'));
      }, 5000);

      this.authResolver = (response) => {
        // WS2 sends: {"type":"+","command":"AUTH","args":["AUTH0","sid-in-hex"]}
        if (response.type === '+' &&
            Array.isArray(response.args) &&
            response.args[0] === 'AUTH0') {
          const sid = response.args[1]; // SID is second element in args array
          this.sessionId = sid;
          this.authenticate(sid);
        } else if (response.type === '+' && response.command === 'AUTH') {
          clearTimeout(timeout);
          this.authResolver = null;
          this.authenticated = true;
          console.log('Authenticated successfully');
          resolve(response);
        } else if (response.type === '-' && response.command === 'AUTH') {
          clearTimeout(timeout);
          this.authResolver = null;
          reject(new Error(`Authentication rejected: ${JSON.stringify(response)}`));
        }
      };
    });
  }

  /**
   * Parse incoming JSON message
   */
  parseMessage(data) {
    let message;
    
    if (typeof data === 'string') {
      message = data;
    } else if (data instanceof Buffer) {
      message = data.toString('utf8');
    } else {
      console.log('Unknown data type:', typeof data, data);
      message = String(data);
    }

    console.log('📥 Raw message:', message);
    
    try {
      const json = JSON.parse(message);
      return json;
    } catch (error) {
      console.error('Failed to parse JSON:', error.message);
      throw error;
    }
  }

  /**
   * Handle incoming messages
   */
  handleMessage(data) {
    const response = this.parseMessage(data);
    
    console.log('\n📨 Received:', JSON.stringify(response, null, 2));

    // Call auth resolver if waiting for AUTH
    if (this.authResolver) {
      console.log("Calling authResolver");
      this.authResolver(response);
      return; // Don't process further if auth resolver handled it
    }

    // Handle different message types
    if (response.type === '+') {
      // Positive response
      if (response.command === 'AUTH' ) {
        console.log('✓ Authentication successful');
        this.authenticated = true;
      } else {
        console.log('✓ Success:', response.command, response.args);
      }
    } else if (response.type === '-') {
      // Error response
      console.error('✗ Error:', response.command, response.args);
    } else if (response.type === 'E' || response.type === 'EVENT') {
      // Event
      this.handleEvent(response.event);
    }
  }

  /**
   * Authenticate with server
   */
  authenticate(iv) {
    try {
      const ivBuffer = Buffer.from(iv, 'hex');
      
      console.log('  IV:', ivBuffer.toString('hex'));

      const cipher = createCipheriv(algorithm, key, ivBuffer);
      cipher.setAutoPadding(false);

      const credentials = Buffer.from(`${username}:${password}`, 'utf8');
      const padded = Buffer.alloc(Math.ceil(credentials.length / 16) * 16);
      credentials.copy(padded);
      const encrypted = Buffer.concat([cipher.update(padded), cipher.final()]).toString('hex');

      console.log('  Encrypted:', encrypted.toUpperCase());

      const authCommand = {
        type: 'CMD',
        command: 'AUTH',
        args: {
          iv: iv,
          crypto: encrypted.toUpperCase()
        }
      };

      console.log('📤 Sending AUTH');
      this.sendJSON(authCommand);
      
    } catch (error) {
      console.error('✗ Authentication failed:', error.message);
      throw error;
    }
  }

  /**
   * Handle incoming event
   */
  handleEvent(event) {
    console.log('📬 Event received:');
    console.log('  Head:', event.head);
    console.log('  VSCP Class:', event.class ?? event.vscpClass);
    console.log('  VSCP Type:', event.type ?? event.vscpType);
    console.log('  OBID:', event.obid);
    console.log('  DateTime:', event.datetime ?? event.dateTime);
    console.log('  Timestamp:', event.timestamp_ns ?? event.timestamp);
    console.log('  GUID:', event.guid);
    console.log('  Data:', event.data);
    console.log('  Note:', event.note || '');
  }

  /**
   * Send command and wait for response
   */
  async sendCommand(command, args = {}, timeout = 5000, message = null) {
    if (!this.isOpen) {
      throw new Error('WebSocket is not open');
    }

    const cmd = {
      type: 'CMD',
      command: command,
      args: args
    };

    console.log('\n📤 Sending command:', command);

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        handler.remove();
        reject(new Error(`Command timeout: ${command}`));
      }, timeout);

      const handler = {
        fn: (data) => {
          const response = this.parseMessage(data);
          
          // Check if this is a response for our command
          if ((response.type === '+' || response.type === '-') && 
              (response.command === command || response.op === command)) {
            clearTimeout(timeoutId);
            this.ws.removeListener('message', handler.fn);
            if (response.type === '-') reject(new Error(`Command rejected: ${JSON.stringify(response)}`));
            else resolve(response);
          }
        },
        remove: () => {
          this.ws.removeListener('message', handler.fn);
        }
      };

      this.ws.on('message', handler.fn);
      this.sendJSON(message || cmd);
    });
  }

  /**
   * Send JSON message
   */
  sendJSON(obj) {
    if (!this.isOpen) {
      throw new Error('Cannot send - WebSocket is not open');
    }
    const json = JSON.stringify(obj);
    console.log('📡 Sending:', json);
    this.ws.send(json);
  }

  /**
   * Send NOOP command
   */
  async noop() {
    return await this.sendCommand('NOOP');
  }

  /**
   * Get version
   */
  async version() {
    return await this.sendCommand('VERSION');
  }

  /**
   * Get copyright
   */
  async copyright() {
    return await this.sendCommand('COPYRIGHT');
  }

  /**
   * Clear queue
   */
  async clearQueue() {
    return await this.sendCommand('CLRQ');
  }

  /**
   * Open channel
   */
  async open() {
    return await this.sendCommand('OPEN');
  }

  /**
   * Close channel
   */
  async closeChannel() {
    return await this.sendCommand('CLOSE');
  }

  /**
   * Send event
   */
  async sendEvent(event) {
    const eventMsg = {
      type: 'EVENT',
      event: event
    };
    return this.sendCommand('EVENT', {}, 5000, eventMsg);
  }

  /**
   * Set filter
   */
  async setFilter(filter) {
    return await this.sendCommand('SETFILTER', { filter: filter });
  }

  /**
   * Get statistics
   */
  async getStatistics() {
    return await this.sendCommand('STATISTICS');
  }

  /**
   * Get status
   */
  async getStatus() {
    return await this.sendCommand('STATUS');
  }

  /**
   * Get channel ID
   */
  async getChannelId() {
    return await this.sendCommand('CHID');
  }

  /**
   * Close WebSocket connection
   */
  async close() {
    if (this.ws) {
      this.ws.close();
      this.isOpen = false;
      console.log('✓ Connection closed');
    }
  }
}

// Example usage
async function main() {
  const client = new VSCPWebSocketClient_WS2(WS_URL);

  try {
    // Connect and authenticate
    await client.connect();
    console.log('=== Connection established and AUTH received ===');

    if (!client.authenticated) {
      throw new Error('Authentication did not complete');
    }

    console.log('=== Starting WS2 commands ===');

    // Send NOOP command
    const noopResp = await client.noop();
    console.log('NOOP response:', noopResp);
    await new Promise(resolve => setTimeout(resolve, 500));

    // Get version
    const versionResp = await client.version();
    console.log('VERSION response:', versionResp);
    await new Promise(resolve => setTimeout(resolve, 500));

    // Get copyright
    const copyrightResp = await client.copyright();
    console.log('COPYRIGHT response:', copyrightResp);
    await new Promise(resolve => setTimeout(resolve, 500));

    // Clear qaueue
    const clearQueueResp = await client.clearQueue();
    console.log('CLEAR QUEUE response:', clearQueueResp);
    await new Promise(resolve => setTimeout(resolve, 500));

    // Open channel
    const openResp = await client.open();
    console.log('OPEN response:', openResp);
    await new Promise(resolve => setTimeout(resolve, 500));

    // Send an event (WS2 format)
    await client.sendEvent({
      head: 0,
      vscpClass: 30,
      vscpType: 5,
      obid: 0,
      datetime: new Date().toISOString(),
      timestamp: 0,
      guid: 'FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00:00:02:00:00',
      data: [1, 2, 3, 4, 5, 6],
      note: 'Test event from WS2 client'
    });
    console.log('Event sent');
    await new Promise(resolve => setTimeout(resolve, 500));

    // Pause for a while to receive some events
    await new Promise(resolve => setTimeout(resolve, 5000));

    // Close channel
    const closeResp = await client.closeChannel();
    console.log('CLOSE response:', closeResp);
    await new Promise(resolve => setTimeout(resolve, 500));

    // Close connection
    await client.close();

  } catch (error) {
    console.error('❌ Error:', error.message);
    console.error(error.stack);
    await client.close();
    process.exit(1);
  }
}

// Run the example
main();