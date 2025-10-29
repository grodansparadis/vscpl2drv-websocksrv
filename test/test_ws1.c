// Build (Linux):
//   gcc test_ws1.c mongoose.c -o test_ws1 -lssl -lcrypto -lpthread -ldl
//
// Run:
//   ./test_ws1
//
// Notes:
// - Requires Mongoose single-file sources (mongoose.c/.h) in the same dir or include path
// - Requires OpenSSL dev libraries for AES

#include "mongoose.h"
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>

#define WS_URL "ws://localhost:8884/ws1"
#define USERNAME "admin"
#define PASSWORD "secret"
// 16-byte shared key (hex, AES-128)
#define VSCP_KEY_HEX "2DBB079A38985AF00EBEEFE22F9FFA0E"

struct client_state {
  bool authenticated;
  char sid[33];            // 16-byte IV in hex + NUL
  unsigned char key[16];   // AES-128 key (binary)
  const char *username;
  const char *password;
  bool sent_open;
};

static void log_hex(const char *title, const unsigned char *buf, size_t len) {
  printf("%s:", title);
  for (size_t i = 0; i < len; ++i) printf("%02X", buf[i]);
  printf("\n");
}

static int hex2bin(const char *hex, unsigned char *out, size_t out_max) {
  size_t n = strlen(hex);
  if (n % 2) return -1;
  size_t bytes = n / 2;
  if (bytes > out_max) return -2;
  for (size_t i = 0; i < bytes; ++i) {
    char c1 = hex[2*i], c2 = hex[2*i+1];
    int v1 = isdigit((unsigned char)c1) ? c1 - '0' : (tolower((unsigned char)c1) - 'a' + 10);
    int v2 = isdigit((unsigned char)c2) ? c2 - '0' : (tolower((unsigned char)c2) - 'a' + 10);
    if (v1 < 0 || v1 > 15 || v2 < 0 || v2 > 15) return -3;
    out[i] = (unsigned char)((v1 << 4) | v2);
  }
  return (int) bytes;
}

static void bin2hex_upper(const unsigned char *in, size_t in_len, char *out, size_t out_sz) {
  static const char *hex = "0123456789ABCDEF";
  size_t need = in_len * 2 + 1;
  if (out_sz < need) return;
  for (size_t i = 0; i < in_len; ++i) {
    out[2*i]   = hex[(in[i] >> 4) & 0xF];
    out[2*i+1] = hex[in[i] & 0xF];
  }
  out[in_len*2] = '\0';
}

static int aes128_cbc_zeropad_encrypt(
  const unsigned char key[16],
  const unsigned char iv[16],
  const unsigned char *in, size_t in_len,
  unsigned char **out, size_t *out_len
) {
  int ret = -1;
  EVP_CIPHER_CTX *ctx = NULL;
  unsigned char *padded = NULL, *ct = NULL;
  int ct_len = 0, tmp_len = 0;

  // Zero-pad to 16-byte boundary (no extra block if already aligned)
  size_t padded_len = ((in_len + 15) / 16) * 16;
  padded = (unsigned char *) calloc(1, padded_len ? padded_len : 16);
  if (!padded) goto done;
  if (in_len) memcpy(padded, in, in_len);

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) goto done;

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) goto done;
  // Disable PKCS#7 padding; we already zero-padded
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  ct = (unsigned char *) malloc(padded_len + 16);
  if (!ct) goto done;

  if (1 != EVP_EncryptUpdate(ctx, ct, &ct_len, padded, (int)padded_len)) goto done;
  if (1 != EVP_EncryptFinal_ex(ctx, ct + ct_len, &tmp_len)) goto done;
  ct_len += tmp_len;

  *out = ct; ct = NULL;
  *out_len = (size_t) ct_len;
  ret = 0;

done:
  if (ctx) EVP_CIPHER_CTX_free(ctx);
  if (padded) free(padded);
  if (ct) free(ct);
  return ret;
}

static void send_text(struct mg_connection *c, const char *s) {
  printf(">> %s\n", s);
  mg_ws_printf(c, WEBSOCKET_OP_TEXT, "%s", s);
}

static void handle_auth0(struct mg_connection *c, struct client_state *st, const char *sid_hex) {
  // Save SID (IV)
  strncpy(st->sid, sid_hex, sizeof(st->sid) - 1);
  st->sid[sizeof(st->sid) - 1] = 0;

  unsigned char iv[16];
  if (hex2bin(sid_hex, iv, sizeof(iv)) != 16) {
    printf("Bad SID length\n");
    return;
  }

  // Prepare "username:password" and encrypt with AES-128-CBC (zero pad)
  char creds[256];
  snprintf(creds, sizeof(creds), "%s:%s", st->username, st->password);

  unsigned char *ct = NULL; size_t ct_len = 0;
  if (aes128_cbc_zeropad_encrypt(st->key, iv,
                                 (const unsigned char *) creds, strlen(creds),
                                 &ct, &ct_len) != 0) {
    printf("AUTH encrypt failed\n");
    return;
  }

  char ct_hex[1024];
  bin2hex_upper(ct, ct_len, ct_hex, sizeof(ct_hex));
  free(ct);

  char cmd[1200];
  snprintf(cmd, sizeof(cmd), "C;AUTH;%s;%s", sid_hex, ct_hex);
  send_text(c, cmd);
}

static void on_ws_msg(struct mg_connection *c, struct client_state *st, struct mg_ws_message *wm) {
  // Convert to string
  struct mg_str s = wm->data;
  char *msg = (char *) malloc(s.len + 1);
  if (!msg) return;
  memcpy(msg, s.buf, s.len);
  msg[s.len] = 0;
  printf("<< %s\n", msg);

  // Parse: TYPE;CMD;params...
  // Expect: +;AUTH0;sid or +;AUTH1;...
  char *saveptr = NULL;
  char *type = strtok_r(msg, ";", &saveptr);
  char *cmd  = strtok_r(NULL, ";", &saveptr);

  if (type && cmd) {
    if (strcmp(type, "+") == 0 && strcmp(cmd, "AUTH0") == 0) {
      char *sid = strtok_r(NULL, ";", &saveptr);
      if (sid) handle_auth0(c, st, sid);
    } else if (strcmp(type, "+") == 0 && strcmp(cmd, "AUTH1") == 0) {
      st->authenticated = true;
      printf("Authenticated.\n");
      // Send some demo commands
      send_text(c, "C;NOOP");
      send_text(c, "C;VERSION");
      if (!st->sent_open) {
        send_text(c, "C;OPEN");
        st->sent_open = true;
      }
    } else if (strcmp(type, "-") == 0) {
      // Error reply
      printf("Error reply: %s\n", cmd);
    } else if (strcmp(type, "E") == 0) {
      // Event line (entire event is rest of string)
      // Example: E;head,class,type,obid,datetime,timestamp,guid,data...
      printf("Event: %s\n", (cmd ? cmd : ""));
    }
  }

  free(msg);
}

static void fn(struct mg_connection *c, int ev, void *ev_data) {
  struct client_state *st = (struct client_state *) c->fn_data;

  switch (ev) {
    case MG_EV_OPEN:
      // TCP connected
      break;

    case MG_EV_ERROR:
      printf("MG_EV_ERROR: %s\n", (char *) ev_data);
      break;
    case MG_EV_WS_OPEN:
      printf("WebSocket opened: %s\n", WS_URL);
      break;
    case MG_EV_WS_MSG:
      on_ws_msg(c, st, (struct mg_ws_message *) ev_data);
      break;
    case MG_EV_CLOSE:
      printf("Connection closed\n");
      break;
    default:
      break;
  }
}

int main(void) {
  // Prepare client state
  struct client_state st;
  memset(&st, 0, sizeof(st));
  st.username = USERNAME;
  st.password = PASSWORD;

  if (hex2bin(VSCP_KEY_HEX, st.key, sizeof(st.key)) != 16) {
    fprintf(stderr, "Invalid VSCP key hex\n");
    return 1;
  }

  struct mg_mgr mgr;
  mg_mgr_init(&mgr);

  // Connect as WebSocket client
  struct mg_connection *c = mg_ws_connect(&mgr, WS_URL, fn, &st, NULL);
  if (!c) {
    fprintf(stderr, "Failed to connect to %s\n", WS_URL);
    mg_mgr_free(&mgr);
    return 2;
  }

  printf("Connecting to %s ...\n", WS_URL);

  // Poll loop (Ctrl+C to exit)
  for (;;) {
    mg_mgr_poll(&mgr, 100);
  }

  // Never reached
  mg_mgr_free(&mgr);
  return 0;
}