const WebSocket = require('ws');
const {
  createCipheriv,
} = require('node:crypto');

// Configuration
const WS_URL = 'ws://localhost:8884/ws1';
const algorithm = 'aes-128-cbc';
const key = Buffer.from('2DBB079A38985AF00EBEEFE22F9FFA0E', 'hex');
const username = 'admin';
const password = 'secret';

class VSCPWebSocketClient {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.authenticated = false;
    this.sessionId = null;
    this.isOpen = false;
    this.authResolver = null;
  }

  /**
   * Connect to WebSocket server
   */
  async connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url, {
                      perMessageDeflate: false
                });

      // Wait for AUTH0
      this.waitForAuth().then(resolve).catch(reject);          

      this.ws.on('open', () => {
        console.log('✓ Connected to WebSocket server');
        this.isOpen = true;
      });

      this.ws.on('message', (data) => {
        //console.log('📩 Message received (raw):', data.toString()); // Debug
        this.handleMessage(data);
      });

      this.ws.on('error', (error) => {
        console.error('❌ WebSocket error:', error);
        reject(error);
      });

      this.ws.on('close', () => {
        console.log('❌ Connection closed');
        this.isOpen = false;
      });

      
    });
  }

  /**
   * Wait for AUTH0 message from server
   */
  waitForAuth() {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('Authentication timeout - no AUTH0 received'));
      }, 5000);

      this.authResolver = (response) => {
        if (response.type === '+' && response.command === 'AUTH0') {
          clearTimeout(timeout);
          this.authResolver = null;
          resolve(response);
        }
      };
    });
  }

  /**
   * Parse incoming message
   */
  parseMessage(data) {
    let message;
    
    // Check if data is already a string or needs decoding
    if (typeof data === 'string') {
      message = data;
    } else if (data instanceof Buffer) {
      message = data.toString('utf8');
    } else {
      console.log('Unknown data type:', typeof data, data);
      message = String(data);
    }

    console.log('📥 Parsed message:', message); // Debug output
    
    const parts = message.trim().split(';');

    const result = {
      raw: message,
      type: parts[0],
      command: parts[1] || '',
      params: parts.slice(2),
    };

    return result;
  }

  /**
   * Handle incoming messages
   */
  handleMessage(data) {
    const response = this.parseMessage(data);
    
    console.log('\n📨 Received:', response.raw);
    console.log('   Type:', response.type, 'Command:', response.command);
    console.log('   Params:', response.params);

    // Call auth resolver if waiting for AUTH0
    if (this.authResolver) {
      this.authResolver(response);
    }

    if (response.type === '+') {
      // Positive response
      if (response.command === 'AUTH0') {
        console.log('🔐 Server requests authentication');
        this.sessionId = response.params[0];
        this.authenticate(this.sessionId);
      } else if (response.command === 'AUTH1') {
        console.log('✓ Authentication successful');
        this.authenticated = true;
      }
    } else if (response.type === '-') {
      // Error response
      console.error('✗ Error:', response.command, response.params.join(';'));
    } else if (response.type === 'E') {
      // Event
      this.handleEvent(response.command);
    }
  }

  /**
   * Authenticate with server
   */
  async authenticate(iv) {
    try {
      const ivBuffer = Buffer.from(iv, 'hex');
      
      console.log('  IV:', ivBuffer.toString('hex'));
      console.log('  Key:', key.toString('hex'));

      const cipher = createCipheriv(algorithm, key, ivBuffer);
      cipher.setAutoPadding(false);

      const credentials = `${username}:${password}`;
      let encrypted = cipher.update(credentials, 'utf8', 'hex');
      
      // Pad to block size (16 bytes)
      const paddingLength = 16 - (credentials.length % 16);
      encrypted += cipher.update('\0'.repeat(paddingLength), 'utf8', 'hex');
      encrypted += cipher.final('hex');

      console.log('  Encrypted:', encrypted.toUpperCase());

      const authCommand = `C;AUTH;${iv};${encrypted.toUpperCase()}`;
      console.log('📤 Sending AUTH:', authCommand);
      this.send(authCommand);
      
    } catch (error) {
      console.error('✗ Authentication failed:', error.message);
      throw error;
    }
  }

  /**
   * Handle incoming event
   */
  handleEvent(eventData) {
    //console.log('--- Event Received ---', eventData);
    const fields = eventData.split(',');
    console.log('📬 Event received:');
    console.log('  Head:', fields[0]);
    console.log('  Class:', fields[1]);
    console.log('  Type:', fields[2]);
    console.log('  OBID:', fields[3]);
    console.log('  DateTime:', fields[4]);
    console.log('  Timestamp:', fields[5]);
    console.log('  GUID:', fields[6]);
    console.log('  Data:', fields.slice(7).join(', '));
  }

  /**
   * Send command and wait for response
   */
  async sendCommand(command, timeout = 5000) {
    if (!this.isOpen) {
      throw new Error('WebSocket is not open');
    }

    const fullCommand = command.startsWith('C;') ? command : `C;${command}`;
    
    console.log('\n📤 Sending:', fullCommand);

    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        handler.remove();
        reject(new Error(`Command timeout: ${command}`));
      }, timeout);

      const handler = {
        fn: (data) => {
          const response = this.parseMessage(data);
          
          // Check if this is a response (not an event)
          if (response.type === '+' || response.type === '-') {
            clearTimeout(timeoutId);
            this.ws.removeListener('message', handler.fn);
            resolve(response);
          }
        },
        remove: () => {
          this.ws.removeListener('message', handler.fn);
        }
      };

      this.ws.on('message', handler.fn);
      this.send(fullCommand);
    });
  }

  /**
   * Send raw message
   */
  send(message) {
    if (!this.isOpen) {
      console.error('Cannot send - WebSocket is not open');
      return;
    }
    this.ws.send(message);
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
  async sendEvent(head, vscpClass, vscpType, guid, data = []) {
    const now = new Date().toISOString();
    const eventStr = `E;${head},${vscpClass},${vscpType},0,${now},0,${guid},${data.join(',')}`;
    this.send(eventStr);
  }

  /**
   * Close WebSocket connection
   */
  async close() {
    if (this.ws && this.isOpen) {
      this.ws.close();
      this.isOpen = false;
      console.log('✓ Connection closed');
    }
  }
}

// Example usage
async function main() {
  const client = new VSCPWebSocketClient(WS_URL);

  try {
    // Connect and authenticate
    await client.connect();
    console.log('Connection established and AUTH0 received');

    // Wait a bit for authentication to complete
    await new Promise(resolve => setTimeout(resolve, 2000));

    if (!client.authenticated) {
      throw new Error('Authentication did not complete');
    }

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

    // Open channel
    const openResp = await client.open();
    console.log('OPEN response:', openResp);
    await new Promise(resolve => setTimeout(resolve, 500));

    // Send an event
    await client.sendEvent(
      0,
      30,
      5,
      'FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00:00:02:00:00',
      [1, 2, 3, 4, 5, 6]
    );
    await new Promise(resolve => setTimeout(resolve, 500));

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