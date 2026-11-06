// Build (Linux):
//   gcc test_ws2.c mongoose.c -o test_ws2 -lssl -lcrypto -lpthread -ldl
//
// Run:
//   ./test_ws2
//
// Notes:
// - Requires Mongoose single-file sources (mongoose.c/.h) in the same dir or include path
// - Requires OpenSSL dev libraries for AES
// - WS2 uses JSON format instead of semicolon-separated strings

#include "mongoose.h"
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>
#include <signal.h>

static volatile sig_atomic_t stopped = 0;
static void handle_signal(int signal_number) { (void) signal_number; stopped = 1; }

#define WS_URL   "ws://localhost:8884/ws2"
#define USERNAME "admin"
#define PASSWORD "secret"
// 16-byte shared key (hex, AES-128)
#define VSCP_KEY_HEX "2DBB079A38985AF00EBEEFE22F9FFA0E"

struct client_state {
  bool authenticated;
  char sid[33];          // 16-byte IV in hex + NUL
  unsigned char key[16]; // AES-128 key (binary)
  const char *username;
  const char *password;
  bool sent_open;
  bool done;
  bool failed;
  bool received_event;
  bool event_sent;
  const char *url;
};

/////////////////////////////////////////////////////////////////////////////////
// Utility functions
/////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////
// log_hex
//

static void
log_hex(const char *title, const unsigned char *buf, size_t len)
{
  printf("%s:", title);
  for (size_t i = 0; i < len; ++i)
    printf("%02X", buf[i]);
  printf("\n");
}

/////////////////////////////////////////////////////////////////////////////////
// hex2bin
//

static int
hex2bin(const char *hex, unsigned char *out, size_t out_max)
{
  size_t n = strlen(hex);
  if (n % 2)
    return -1;
  size_t bytes = n / 2;
  if (bytes > out_max)
    return -2;
  for (size_t i = 0; i < bytes; ++i) {
    char c1 = hex[2 * i], c2 = hex[2 * i + 1];
    int v1 = isdigit((unsigned char) c1) ? c1 - '0' : (tolower((unsigned char) c1) - 'a' + 10);
    int v2 = isdigit((unsigned char) c2) ? c2 - '0' : (tolower((unsigned char) c2) - 'a' + 10);
    if (v1 < 0 || v1 > 15 || v2 < 0 || v2 > 15)
      return -3;
    out[i] = (unsigned char) ((v1 << 4) | v2);
  }
  return (int) bytes;
}

/////////////////////////////////////////////////////////////////////////////////
// bin2hex_upper
//

static void
bin2hex_upper(const unsigned char *in, size_t in_len, char *out, size_t out_sz)
{
  static const char *hex = "0123456789ABCDEF";
  size_t need            = in_len * 2 + 1;
  if (out_sz < need)
    return;
  for (size_t i = 0; i < in_len; ++i) {
    out[2 * i]     = hex[(in[i] >> 4) & 0xF];
    out[2 * i + 1] = hex[in[i] & 0xF];
  }
  out[in_len * 2] = '\0';
}

/////////////////////////////////////////////////////////////////////////////////
// aes128_cbc_zeropad_encrypt
//

static int
aes128_cbc_zeropad_encrypt(const unsigned char key[16],
                           const unsigned char iv[16],
                           const unsigned char *in,
                           size_t in_len,
                           unsigned char **out,
                           size_t *out_len)
{
  int ret               = -1;
  EVP_CIPHER_CTX *ctx   = NULL;
  unsigned char *padded = NULL, *ct = NULL;
  int ct_len = 0, tmp_len = 0;

  // Zero-pad to 16-byte boundary
  size_t padded_len = ((in_len + 15) / 16) * 16;
  padded            = (unsigned char *) calloc(1, padded_len ? padded_len : 16);
  if (!padded)
    goto done;
  if (in_len)
    memcpy(padded, in, in_len);

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    goto done;

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    goto done;
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  ct = (unsigned char *) malloc(padded_len + 16);
  if (!ct)
    goto done;

  if (1 != EVP_EncryptUpdate(ctx, ct, &ct_len, padded, (int) padded_len))
    goto done;
  if (1 != EVP_EncryptFinal_ex(ctx, ct + ct_len, &tmp_len))
    goto done;
  ct_len += tmp_len;

  *out     = ct;
  ct       = NULL;
  *out_len = (size_t) ct_len;
  ret      = 0;

done:
  if (ctx)
    EVP_CIPHER_CTX_free(ctx);
  if (padded)
    free(padded);
  if (ct)
    free(ct);
  return ret;
}

/////////////////////////////////////////////////////////////////////////////////
// send_json
//

static void
send_json(struct mg_connection *c, const char *json)
{
  printf(">> %s\n", json);
  mg_ws_printf(c, WEBSOCKET_OP_TEXT, "%s", json);
}

/////////////////////////////////////////////////////////////////////////////////
// handle_auth0
//

static void
handle_auth0(struct mg_connection *c, struct client_state *st, const char *sid_hex)
{
  // Save SID (IV)
  strncpy(st->sid, sid_hex, sizeof(st->sid) - 1);
  st->sid[sizeof(st->sid) - 1] = 0;

  unsigned char iv[16];
  if (hex2bin(sid_hex, iv, sizeof(iv)) != 16) {
    printf("Bad SID length\n");
    st->failed = st->done = true;
    return;
  }

  // Prepare "username:password" and encrypt with AES-128-CBC (zero pad)
  char creds[256];
  if (snprintf(creds, sizeof(creds), "%s:%s", st->username, st->password) >= (int) sizeof(creds)) {
    fprintf(stderr, "Credentials exceed client buffer size\n");
    st->failed = st->done = true;
    return;
  }

  unsigned char *ct = NULL;
  size_t ct_len     = 0;
  if (aes128_cbc_zeropad_encrypt(st->key, iv, (const unsigned char *) creds, strlen(creds), &ct, &ct_len) != 0) {
    printf("AUTH encrypt failed\n");
    st->failed = st->done = true;
    return;
  }

  char ct_hex[1024];
  bin2hex_upper(ct, ct_len, ct_hex, sizeof(ct_hex));
  free(ct);

  // Build JSON: {"type":"CMD","command":"AUTH","args":{"iv":"...","crypto":"..."}}
  char cmd[2048];
  snprintf(cmd,
           sizeof(cmd),
           "{\"type\":\"CMD\",\"command\":\"AUTH\",\"args\":{\"iv\":\"%s\",\"crypto\":\"%s\"}}",
           sid_hex,
           ct_hex);
  send_json(c, cmd);
}

/////////////////////////////////////////////////////////////////////////////////
// on_ws_msg
//

static void
on_ws_msg(struct mg_connection *c, struct client_state *st, struct mg_ws_message *wm)
{
  static int cnt = 0;  // Receive event counter
  // Convert to string
  struct mg_str s = wm->data;
  char *msg       = (char *) malloc(s.len + 1);
  if (!msg) {
    fprintf(stderr, "Unable to allocate message buffer\n");
    st->failed = st->done = true;
    return;
  }

  memcpy(msg, s.buf, s.len);
  msg[s.len] = 0;
  printf("<< %s\n", msg);

  // Parse JSON using Mongoose's built-in parser
  struct mg_str json = mg_str(msg);

  // Get type field
  char *type = mg_json_get_str(json, "$.type");

  // Get command field
  char *command = mg_json_get_str(json, "$.command");
  char *arg0 = mg_json_get_str(json, "$.args[0]");

  if (!type) {
    fprintf(stderr, "Invalid WS2 message: missing type\n");
    st->failed = st->done = true;
  }
  // Accept AUTH0 with or without an explicit command field.
  else if (strcmp(type, "+") == 0 && arg0 && strcmp(arg0, "AUTH0") == 0) {
    char *sid = mg_json_get_str(json, "$.args[1]");
    if (sid) {
      printf("Received AUTH0, SID: %s\n", sid);
      handle_auth0(c, st, sid);
      free(sid);
    }
    else {
      fprintf(stderr, "Missing session ID in AUTH0\n");
      st->failed = st->done = true;
    }
  }
  else if (strcmp(type, "+") == 0 && command && strcmp(command, "AUTH") == 0) {
    st->authenticated = true;
    printf("✓ Authenticated successfully\n");

    // Send demo commands
    send_json(c, "{\"type\":\"CMD\",\"command\":\"NOOP\",\"args\":{}}");
    send_json(c, "{\"type\":\"CMD\",\"command\":\"VERSION\",\"args\":{}}");
    send_json(c, "{\"type\":\"CMD\",\"command\":\"COPYRIGHT\",\"args\":{}}");

    if (!st->sent_open) {
      send_json(c, "{\"type\":\"CMD\",\"command\":\"OPEN\",\"args\":{}}");
      st->sent_open = true;
    }
  }
  else if (strcmp(type, "+") == 0 && command && strcmp(command, "OPEN") == 0) {
    send_json(c, "{\"type\":\"EVENT\",\"event\":{\"head\":0,\"vscpClass\":30,\"vscpType\":5,"
                 "\"obid\":0,\"datetime\":\"2026-01-01T00:00:00Z\",\"timestamp\":0,"
                 "\"guid\":\"FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00:00:02:00:00\",\"data\":[1,2,3,4,5,6]}}");
  }
  else if (strcmp(type, "+") == 0 && command && strcmp(command, "CLOSE") == 0) {
    st->done = true;
  }
  else if (strcmp(type, "+") == 0 && command && strcmp(command, "EVENT") == 0) {
    // Event
    printf("📬 Event sent\n");
    st->event_sent = true;
  }
  else if (strcmp(type, "+") == 0) {
    // Success response
    printf("✓ Success: %s\n", command ? command : "(no command)");
  }
  else if (strcmp(type, "-") == 0) {
    // Error reply
    printf("✗ Error reply: %s\n", command ? command : "(no command)");
    st->failed = st->done = true;
  }
  else if (strcmp(type, "EVENT") == 0 || strcmp(type, "E") == 0) {
    // Event
    printf("📬 Event received %d\n", cnt++);
    st->received_event = true;
    // Could parse event.vscpClass, event.vscpType, etc.
  }

  free(arg0);
  free(command);
  free(type);
  free(msg);
}

/////////////////////////////////////////////////////////////////////////////////
// fn - WebSocket event handler
//

static void
fn(struct mg_connection *c, int ev, void *ev_data)
{
  struct client_state *st = (struct client_state *) c->fn_data;

  switch (ev) {
    case MG_EV_OPEN:
      break;
    case MG_EV_ERROR:
      printf("MG_EV_ERROR: %s\n", (char *) ev_data);
      st->failed = st->done = true;
      break;
    case MG_EV_WS_OPEN:
      printf("✓ Connected to WS2 server: %s\n", st->url);
      break;
    case MG_EV_WS_MSG:
      on_ws_msg(c, st, (struct mg_ws_message *) ev_data);
      break;
    case MG_EV_CLOSE:
      printf("❌ Connection closed\n");
      if (!st->done) st->failed = true;
      st->done = true;
      break;
    default:
      break;
  }
}

/////////////////////////////////////////////////////////////////////////////////
// main
//

int
main(void)
{
  // Prepare client state
  struct client_state st;
  memset(&st, 0, sizeof(st));
  st.username = getenv("VSCP_USERNAME") ? getenv("VSCP_USERNAME") : USERNAME;
  st.password = getenv("VSCP_PASSWORD") ? getenv("VSCP_PASSWORD") : PASSWORD;
  st.url = getenv("VSCP_WS_URL") ? getenv("VSCP_WS_URL") : WS_URL;
  const char *key = getenv("VSCP_KEY_HEX") ? getenv("VSCP_KEY_HEX") : VSCP_KEY_HEX;

  if (hex2bin(key, st.key, sizeof(st.key)) != 16) {
    fprintf(stderr, "Invalid VSCP key hex\n");
    return 1;
  }
  if (mg_url_is_ssl(st.url)) {
    fprintf(stderr, "This sample supports ws:// only; use the Python or JavaScript client for wss://.\n");
    return 1;
  }

  struct mg_mgr mgr;
  mg_mgr_init(&mgr);

  // Connect as WebSocket client
  struct mg_connection *c = mg_ws_connect(&mgr, st.url, fn, &st, NULL);
  if (!c) {
    fprintf(stderr, "Failed to connect to %s\n", st.url);
    mg_mgr_free(&mgr);
    return 2;
  }

  printf("Connecting to %s ...\n", st.url);
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);
  const uint64_t started = mg_millis();
  const char *duration = getenv("VSCP_TEST_SECONDS");
  char *end = NULL;
  unsigned long seconds = duration ? strtoul(duration, &end, 10) : 0;
  if (duration && (!*duration || *end || seconds > 3600)) {
    fprintf(stderr, "VSCP_TEST_SECONDS must be an integer from 0 to 3600\n");
    mg_mgr_free(&mgr);
    return 1;
  }
  uint64_t closing = 0;

  // Poll loop (Ctrl+C to exit)
  while (!st.done) {
    mg_mgr_poll(&mgr, 100);
    if (st.done) break;
    uint64_t now = mg_millis();
    if (!st.authenticated && now - started > 10000) {
      fprintf(stderr, "Authentication timed out\n");
      st.failed = true;
      break;
    }
    if (!closing && (stopped || (seconds && now - started >= seconds * 1000ULL))) {
      send_json(c, "{\"type\":\"CMD\",\"command\":\"CLOSE\",\"args\":{}}");
      closing = now;
    }
    if (closing && now - closing > 5000) {
      fprintf(stderr, "CLOSE timed out\n");
      st.failed = true;
      break;
    }
  }

  if (seconds && (!st.authenticated || !st.event_sent || !st.received_event)) {
    fprintf(stderr, "Test did not complete authentication and bidirectional events\n");
    st.failed = true;
  }
  mg_mgr_free(&mgr);
  return st.failed ? 1 : 0;
}