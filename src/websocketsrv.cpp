// websocketserver.cpp
//
// This file is part of the VSCP (https://www.vscp.org)
//
// The MIT License (MIT)
//
// Copyright © 2000-2025 Ake Hedman, Grodans Paradis AB
// <info@grodansparadis.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#ifdef __GNUG__
// #pragma implementation
#endif

#define _POSIX

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <mongoose.h>
#include <expat.h>
#include <json.hpp> // Needs C++11  -std=c++11

#include <version.h>
#include <vscp.h>
#include <vscp_aes.h>
#include <vscp_debug.h>
#include <vscphelper.h>

#include "websocketsrv.h"

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#define XML_BUFF_SIZE 0xffff

// for convenience
using json = nlohmann::json;

///////////////////////////////////////////////////
//                 GLOBALS
///////////////////////////////////////////////////

// Webserver
// extern struct mg_mgr gmgr;

// Linked list of all active sessions. (webserv.h)
// extern struct websrv_Session *gp_websrv_sessions;

// Session structure for REST API
// extern struct websrv_rest_session *gp_websrv_rest_sessions;

// Prototypes
// int
// webserv_url_decode(const char *src, int src_len, char *dst, int dst_len, int is_form_url_encoded);

// void
// webserv_util_sendheader(struct mg_connection *nc, const int returncode, const char *content);

////////////////////////////////////////////////////
//            Forward declarations
////////////////////////////////////////////////////

//----------------------------------------------------
//                      ws1
//----------------------------------------------------
// void
// websocketsrv::ws1_command(struct mg_connection *conn, struct websock_session *pSession, std::string &strCmd);

// bool
// ws1_message(struct mg_connection *conn, websock_session *pSession, std::string &strWsPkt);

//----------------------------------------------------
//                      ws2
//----------------------------------------------------

// bool
// ws2_command(struct mg_connection *conn, struct websock_session *pSession, std::string &strCmd, json &obj);

// bool
// ws2_message(struct mg_connection *conn, websock_session *pSession, std::string &strWsPkt);

///////////////////////////////////////////////////
//                 WEBSOCKETS
///////////////////////////////////////////////////

// Linked list of websocket sessions
// Protected by the websocketSessionMutex
// static struct websock_session *gp_websock_sessions;

CWebsockSession::CWebsockSession(void)
{
  m_wstypes    = WS_TYPE_1; // ws1 is default
  m_conn_state = WEBSOCK_CONN_STATE_NULL;
  memset(m_websocket_key, 0, 33);
  memset(m_sid, 0, 33);
  m_version      = 0;
  lastActiveTime = 0;
  m_pClientItem  = NULL;
  m_strConcatenated.clear();

  // Generate the sid
  unsigned char iv[16];
  char hexiv[33];
  getRandomIV(iv, 16); // Generate 16 random bytes
  memset(hexiv, 0, sizeof(hexiv));
  vscp_byteArray2HexStr(hexiv, iv, 16);

  memset(m_sid, 0, sizeof(pSession->m_sid));
  memcpy(m_sid, hexiv, 32);
  memset(m_websocket_key, 0, sizeof(m_websocket_key));

  // Init.
  strcpy(m_websocket_key, ws_key); // Save key

  // Attach and initiate client object
  m_pClientItem = new CClientItem(); // Create client
  if (NULL == m_pClientItem) {
    syslog(LOG_ERR, "[Websockets] New session: Unable to create client object.");
    delete pSession;
    return NULL;
  }

  m_pClientItem->bAuthenticated = false;          // Not authenticated in yet
  vscp_clearVSCPFilter(&m_pClientItem->m_filter); // Clear filter

  // This is an active client
  m_pClientItem->m_bOpen         = false;
  m_pClientItem->m_dtutc         = vscpdatetime::Now();
  m_pClientItem->m_type          = CLIENT_ITEM_INTERFACE_TYPE_CLIENT_WEBSOCKET;
  m_pClientItem->m_strDeviceName = ("Websocket client level II driver.");
};

CWebsockSession::~CWebsockSession(void)
{
  // Deallocate the client item if it exists
  if (nullptr != m_pClientItem) {
    delete m_pClientItem; // Delete client item
    m_pClientItem = NULL;
  }
};

// ----------------------------------------------------------------------------

// w2msg - Message holder for W2

/////////////////////////////////////////////////////////////////////////////////
// Constructor
//
// This is used to hold a message that is sent to the websocket client.
// It can be a command, response or event.
//

w2msg::w2msg(void)
{
  m_type = MSG_TYPE_COMMAND;
  memset(&m_ex, 0., sizeof(vscpEventEx));
};

////////////////////////////////////////////////////////////////////////////////////
// Destructor
//

w2msg::~w2msg(void)
{
  ;
}

// ----------------------------------------------------------------------------

//////////////////////////////////////////////////////////////////////////////////
// Constructor
//

websocketsrv::websocketsrv(void)
{
  // Initialize mutex
  pthread_mutex_init(&m_websocketSessionMutex, NULL);

  // Set default values
  m_url       = "ws://localhost:8000";
  m_web_root  = ".";
  m_ca_path   = "/etc/vscp/certs/ca.pem";
  m_cert_path = "/etc/vscp/certs/cert.pem";
  m_key_path  = "/etc/vscp/certs/key.pem";

  m_mgr = {}; // Initialize mongoose event manager
}

////////////////////////////////////////////////////////////////////////////////
// Destructor
//

websocketsrv::~websocketsrv(void)
{
  ;
}

////////////////////////////////////////////////////////////////////////////////
// init
//

int
websocketsrv::init(std::string &url,
                   std::string &web_root,
                   std::string &ca_path,
                   std::string &cert_path,
                   std::string &key_path)
{
  // Set values
  m_url       = url;
  m_web_root  = web_root;
  m_ca_path   = ca_path;
  m_cert_path = cert_path;
  m_key_path  = key_path;

  // Initialize mutex
  pthread_mutex_init(&m_websocketSessionMutex, NULL);

  return VSCP_ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// start
//

int
websocketsrv::start(void)
{

  mg_mgr_init(&m_mgr); // Initialise mongoose event manager
  printf("Starting WS listener on %s/websocket\n", s_listen_on);
  mg_http_listen(&mgr, s_listen_on, fn, NULL); // Create HTTP listener
  for (;;)
    mg_mgr_poll(&mgr, 1000); // Infinite event loop

  return VSCP_ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// stop
//

int
websocketsrv::stop(void)
{
  mg_mgr_free(&m_mgr);
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// websock_authentication
//
// w1 client sends
//      "AUTH;iv;AES128("username:password) using main key
// w2 client sends
//      JSON equivalent

int
websocketsrv::authentication(struct mg_connection *conn, std::string &strIV, std::string &strCrypto)
{
  uint8_t buf[2048], secret[2048];
  uint8_t iv[16];
  std::string strUser, strPassword;

  bool bValidHost = false;

  // Check pointers
  if ((NULL == conn) || (NULL == m_pSession)) {
    syslog(LOG_ERR,
           "[Websocket Client] Authentication: Invalid "
           "pointers. ");
    return false;
  }

  CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;

  if (0 == vscp_hexStr2ByteArray(iv, 16, (const char *) strIV.c_str())) {
    syslog(LOG_ERR,
           "[Websocket Client] Authentication: No room "
           "for iv block. ");
    return false; // Not enough room in buffer
  }

  size_t len;
  if (0 == (len = vscp_hexStr2ByteArray(secret, strCrypto.length(), (const char *) strCrypto.c_str()))) {
    syslog(LOG_ERR,
           "[Websocket Client] Authentication: No room "
           "for crypto block. ");
    return false; // Not enough room in buffer
  }

  memset(buf, 0, sizeof(buf));
  AES_CBC_decrypt_buffer(AES128, buf, secret, len, m_key, iv);

  std::string str = std::string((const char *) buf);
  std::deque<std::string> tokens;
  vscp_split(tokens, str, ":");

  // Get username
  if (tokens.empty()) {
    syslog(LOG_ERR,
           "[Websocket Client] Authentication: Missing "
           "username from client. ");
    return false; // No username
  }

  strUser = tokens.front();
  tokens.pop_front();
  vscp_trim(strUser);

  // Get password
  if (tokens.empty()) {
    syslog(LOG_ERR,
           "[Websocket Client] Authentication: Missing "
           "password from client. ");
    return false; // No username
  }

  strPassword = tokens.front();
  tokens.pop_front();
  vscp_trim(strPassword);

  // Check if user is valid
  CUserItem *pUserItem = m_userList.getUser(strUser);
  if (NULL == pUserItem) {
    syslog(LOG_ERR,
           "[Websocket Client] Authentication: CUserItem "
           "allocation problem ");
    return false;
  }

  // Check if remote ip is valid
  bValidHost = pUserItem->isAllowedToConnect(inet_addr(conn->rem));

  if (!bValidHost) {
    // Log valid login
    syslog(LOG_ERR,
           "[Websocket Client] Authentication: Host "
           "[%s] NOT allowed to connect.",
           conn->rem);
    return false;
  }

  if (!vscp_isPasswordValid(pUserItem->getPassword(), strPassword)) {
    syslog(LOG_ERR,
           "[Websocket Client] Authentication: User %s at host "
           "[%s] gave wrong password.",
           (const char *) strUser.c_str(),
           con->rem);
    return false;
  }

  m_pSession->m_pClientItem->bAuthenticated = true;

  // Add user to client
  m_pSession->m_pClientItem->m_pUserItem = pUserItem;

  // Copy in the user filter
  memcpy(&m_pSession->m_pClientItem->m_filter, pUserItem->getUserFilter(), sizeof(vscpEventFilter));

  // Log valid login
  syslog(LOG_ERR,
         "[Websocket Client] Authentication: Host [%s] "
         "User [%s] allowed to connect.",
         con->rem,
         (const char *) strUser.c_str());

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// newSession
//

// websock_session *
// websocketsrv::newSession(const struct mg_connection *conn)
// {
//   const char *pHeader;
//   char ws_version[10];
//   char ws_key[33];
//   websock_session *pSession = NULL;

//   // Check pointers
//   if (NULL == conn)
//     return NULL;

//   // user
//   memset(ws_version, 0, sizeof(ws_version));
//   if (NULL != (pHeader = mg_get_header(conn, "Sec-WebSocket-Version"))) {
//     strncpy(ws_version, pHeader, std::min(strlen(pHeader) + 1, sizeof(ws_version)));
//   }
//   memset(ws_key, 0, sizeof(ws_key));
//   if (NULL != (pHeader = mg_get_header(conn, "Sec-WebSocket-Key"))) {
//     strncpy(ws_key, pHeader, std::min(strlen(pHeader) + 1, sizeof(ws_key)));
//   }

//   // create fresh session
//   pSession = new websock_session;
//   if (NULL == pSession) {
//     syslog(LOG_ERR, "[Websockets] New session: Unable to create session object.");
//     return NULL;
//   }

//   // Generate the sid
//   unsigned char iv[16];
//   char hexiv[33];
//   getRandomIV(iv, 16); // Generate 16 random bytes
//   memset(hexiv, 0, sizeof(hexiv));
//   vscp_byteArray2HexStr(hexiv, iv, 16);

//   memset(pSession->m_sid, 0, sizeof(pSession->m_sid));
//   memcpy(pSession->m_sid, hexiv, 32);
//   memset(pSession->m_websocket_key, 0, sizeof(pSession->m_websocket_key));

//   // Init.
//   strcpy(pSession->m_websocket_key, ws_key); // Save key
//   pSession->m_conn       = (struct mg_connection *) conn;
//   pSession->m_conn_state = WEBSOCK_CONN_STATE_CONNECTED;
//   pSession->m_version    = atoi(ws_version); // Store protocol version

//   pSession->m_pClientItem = new CClientItem(); // Create client
//   if (NULL == pSession->m_pClientItem) {
//     syslog(LOG_ERR, "[Websockets] New session: Unable to create client object.");
//     delete pSession;
//     return NULL;
//   }

//   pSession->m_pClientItem->bAuthenticated = false;          // Not authenticated in yet
//   vscp_clearVSCPFilter(&pSession->m_pClientItem->m_filter); // Clear filter

//   // This is an active client
//   pSession->m_pClientItem->m_bOpen         = false;
//   pSession->m_pClientItem->m_dtutc         = vscpdatetime::Now();
//   pSession->m_pClientItem->m_type          = CLIENT_ITEM_INTERFACE_TYPE_CLIENT_WEBSOCKET;
//   pSession->m_pClientItem->m_strDeviceName = ("Internal websocket client.");

//   // Add the client to the Client List
//   pthread_mutex_lock(&m_clientList.m_mutexItemList);
//   if (!addClient(pSession->m_pClientItem)) {
//     // Failed to add client
//     delete pSession->m_pClientItem;
//     pSession->m_pClientItem = NULL;
//     pthread_mutex_unlock(&m_clientList.m_mutexItemList);
//     syslog(LOG_ERR, ("Websocket server: Failed to add client. Terminating thread."));
//     return NULL;
//   }
//   pthread_mutex_unlock(&m_clientList.m_mutexItemList);

//   pthread_mutex_lock(&m_mutex_websocketSession);
//   m_websocketSessions.push_back(pSession);
//   pthread_mutex_unlock(&m_mutex_websocketSession);

//   // Use the session object as user data
//   mg_set_user_connection_data(pSession->m_conn, (void *) pSession);

//   return pSession;
// }

///////////////////////////////////////////////////////////////////////////////
// sendEvent
//
// Send event to all other clients.
//

int
websocketsrv::sendEvent(struct mg_connection *conn, vscpEvent *pev)
{
  // Check pointers
  if (NULL == conn) {
    syslog(LOG_ERR, "Internal error: websock_sendevent - conn == NULL");
    return false;
  }

  CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;
  if (NULL == m_pSession) {
    syslog(LOG_ERR, "Internal error: websock_sendevent - pSession == NULL");
    return false;
  }

  if (NULL == pev) {
    syslog(LOG_ERR, "Internal error: websock_sendevent - pEvent == NULL");
    return false;
  }

  return sendEvent(pSession->m_pClientItem, pev);
}

///////////////////////////////////////////////////////////////////////////////
// sendEventEx
//
// Send event to all other clients.
//

bool
websocketsrv::sendEventEx(struct mg_connection *conn, vscpEventEx *pex)
{
  // Check pointers
  if (NULL == conn) {
    syslog(LOG_ERR, "Internal error: websock_sendevent - conn == NULL");
    return false;
  }

  CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;
  if (NULL == m_pSession) {
    syslog(LOG_ERR, "Internal error: websock_sendevent - pSession == NULL");
    return false;
  }

  if (NULL == pex) {
    syslog(LOG_ERR, "Internal error: websock_sendevent - pEvent == NULL");
    return false;
  }

  return sendEvent(pSession->m_pClientItem, pex);
}

///////////////////////////////////////////////////////////////////////////////
// postIncomingEvent
//

void
websocketsrv::postIncomingEvent(void)
{
  pthread_mutex_lock(&m_mutex_websocketSession);

  std::list<websock_session *>::iterator iter;
  for (iter = m_websocketSessions.begin(); iter != m_websocketSessions.end(); ++iter) {

    websock_session *pSession = *iter;
    if (NULL == pSession) {
      continue;
    }

    // Should be a client item... hmm.... client disconnected
    if (NULL == pSession->m_pClientItem) {
      continue;
    }

    if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED)
      continue;

    if (NULL == pSession->m_conn)
      continue;

    if (pSession->m_pClientItem->m_bOpen && pSession->m_pClientItem->m_clientInputQueue.size()) {

      vscpEvent *pEvent;
      pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);
      pEvent = pSession->m_pClientItem->m_clientInputQueue.front();
      pSession->m_pClientItem->m_clientInputQueue.pop_front();
      pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
      if (NULL != pEvent) {

        // Run event through filter
        if (vscp_doLevel2Filter(pEvent, &pSession->m_pClientItem->m_filter)) {

          // User must be authorized to receive events
          if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
            continue;
          }

          std::string str;
          if (vscp_convertEventToString(str, pEvent)) {

            if (__VSCP_DEBUG_WEBSOCKET_RX) {
              syslog(LOG_DEBUG, "Received ws event %s", str.c_str());
            }

            // Write it out
            if (WS_TYPE_1 == pSession->m_wstypes) {
              str = ("E;") + str;
              mg_ws_send(pSession->m_conn,
                         MG_WEBSOCKET_OPCODE_TEXT,
                         (const char *) str.c_str(),
                         str.length(),
                         WEBSOCKET_OP_TEXT);
            }
            else if (WS_TYPE_2 == pSession->m_wstypes) {
              std::string strEvent;
              vscp_convertEventToJSON(strEvent, pEvent);
              std::string str = vscp_str_format(WS2_EVENT, strEvent.c_str());
              mg_ws_send(pSession->m_conn,
                         MG_WEBSOCKET_OPCODE_TEXT,
                         (const char *) str.c_str(),
                         str.length(),
                         WEBSOCKET_OP_TEXT);
            }
          }
        }

        // Remove the event
        vscp_deleteEvent_v2(&pEvent);

      } // Valid pEvent pointer

    } // events available

  } // for

  pthread_mutex_unlock(&m_mutex_websocketSession);
}

////////////////////////////////////////////////////////////////////////////////
// ws1_connectHandler
//

// int
// websocketsrv::ws1_connectHandler(const struct mg_connection *conn, void *cbdata)
// {
//   struct mg_context *ctx = mg_get_context(conn);
//   int reject             = 1;

//   // Check pointers
//   if (NULL == conn) {
//     return 1;
//   }
//   if (NULL == ctx) {
//     return 1;
//   }

//   mg_lock_context(ctx);
//   websock_session *pSession = websock_new_session(conn);

//   if (NULL != pSession) {
//     reject = 0;
//   }

//   // This is a WS1 type connection
//   pSession->m_wstypes = WS_TYPE_1;

//   mg_unlock_context(ctx);

//   if (__VSCP_DEBUG_WEBSOCKET) {
//     syslog(LOG_ERR, "[Websocket ws1] WS1 Connection: client %s", (reject ? "rejected" : "accepted"));
//   }

//   return reject;
// }

////////////////////////////////////////////////////////////////////////////////
// ws1_closeHandler
//

// void
// websocketsrv::ws1_closeHandler(const struct mg_connection *conn, void *cbdata)
// {
//   struct mg_context *ctx    = mg_get_context(conn);
//   CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;

//   // Check pointers
//   if (NULL == conn) {
//     return;
//   }

//   if (NULL == pSession) {
//     return;
//   }

//   if (pSession->m_conn != conn) {
//     return;
//   }

//   if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
//     return;
//   }

//   mg_lock_context(ctx);

//   // Record activity
//   pSession->lastActiveTime = time(NULL);

//   pSession->m_conn_state = WEBSOCK_CONN_STATE_NULL;
//   pSession->m_conn       = NULL;
//   m_clientList.removeClient(pSession->m_pClientItem);
//   pSession->m_pClientItem = NULL;

//   pthread_mutex_lock(&m_mutex_websocketSession);
//   // Remove session
//   m_websocketSessions.remove(pSession);
//   delete pSession;
//   pthread_mutex_unlock(&m_mutex_websocketSession);

//   mg_unlock_context(ctx);
// }

////////////////////////////////////////////////////////////////////////////////
// ws1_readyHandler
//

// void
// websocketsrv::ws1_readyHandler(struct mg_connection *conn, void *cbdata)
// {
//   // Check pointers
//   if (NULL == conn) {
//     return;
//   }

//   CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;
//   if (NULL == pSession) {
//     return;
//   }

//   if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
//     return;
//   }

//   // Record activity
//   pSession->lastActiveTime = time(NULL);

//   // Start authentication
//   std::string str = vscp_str_format(("+;AUTH0;%s"), pSession->m_sid);
//   mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

//   pSession->m_conn_state = WEBSOCK_CONN_STATE_DATA;
// }

////////////////////////////////////////////////////////////////////////////////
// ws1_dataHandler
//

int
websocketsrv::ws1_dataHandler(struct mg_connection *conn, int bits, char *data, size_t len, void *cbdata)
{
  std::string strWsPkt;

  // Check pointers
  if (NULL == conn) {
    return WEB_ERROR;
  }

  CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return WEB_ERROR;
  }

  if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
    return WEB_ERROR;
  }

  // Record activity
  pSession->lastActiveTime = time(NULL);

  switch (((unsigned char) bits) & 0x0F) {

    case MG_WEBSOCKET_OPCODE_CONTINUATION:

      if (__VSCP_DEBUG_WEBSOCKET_RX) {
        syslog(LOG_DEBUG, "Websocket WS1 - opcode = Continuation");
      }

      // Save and concatenate message
      pSession->m_strConcatenated += std::string(data, len);

      // if last process is
      if (1 & bits) {
        try {
          if (!ws1_message(conn, pSession, pSession->m_strConcatenated)) {
            return WEB_ERROR;
          }
        }
        catch (...) {
          syslog(LOG_ERR, "ws1: Exception occurred ws1_message concat");
        }
      }
      break;

    // https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
    case MG_WEBSOCKET_OPCODE_TEXT:
      if (__VSCP_DEBUG_WEBSOCKET_RX) {
        syslog(LOG_DEBUG, "Websocket WS1 - opcode = text[%s]", strWsPkt.c_str());
      }
      if (1 & bits) {
        try {
          strWsPkt = std::string(data, len);
          if (!ws1_message(conn, pSession, strWsPkt)) {
            return WEB_ERROR;
          }
        }
        catch (...) {
          syslog(LOG_ERR, "ws1: Exception occurred ws1_message");
        }
      }
      else {
        // Store first part
        pSession->m_strConcatenated = std::string(data, len);
      }
      break;

    case MG_WEBSOCKET_OPCODE_BINARY:
      if (__VSCP_DEBUG_WEBSOCKET_RX) {
        syslog(LOG_DEBUG, "Websocket WS1 - opcode = BINARY");
      }
      break;

    case MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE:
      if (__VSCP_DEBUG_WEBSOCKET) {
        syslog(LOG_DEBUG, "Websocket WS1 - opcode = Connection close");
      }
      break;

    case MG_WEBSOCKET_OPCODE_PING:
      if (__VSCP_DEBUG_WEBSOCKET_PING) {
        syslog(LOG_DEBUG, "Websocket WS1 - Ping received/Pong sent,");
      }
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_PONG, NULL, 0, WEBSOCKET_OP_TEXT);
      break;

    case MG_WEBSOCKET_OPCODE_PONG:
      if (__VSCP_DEBUG_WEBSOCKET_PING) {
        syslog(LOG_DEBUG, "Websocket WS2 - Pong received/Pung sent,");
      }
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_PING, NULL, 0, WEBSOCKET_OP_TEXT);
      break;

    default:
      break;
  }

  return WEB_OK;
}

///////////////////////////////////////////////////////////////////////////////
// ws1_message
//

int
websocketsrv::ws1_message(struct mg_connection *conn, std::string &strWsPkt)
{
  std::string str;

  // Check pointers
  if (NULL == conn) {
    return false;
  }

  CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return false;
  }

  vscp_trim(strWsPkt);

  switch (strWsPkt[0]) {

    // Command - | 'C' | command type (byte) | data |
    case 'C':
      // Point beyond initial info "C;"
      strWsPkt = vscp_str_right(strWsPkt, strWsPkt.length() - 2);
      try {
        ws1_command(conn, pSession, strWsPkt);
      }
      catch (...) {
        syslog(LOG_ERR, "ws1: Exception occurred ws1_command");
        str = vscp_str_format(("-;C;%d;%s"), (int) WEBSOCK_ERROR_GENERAL, WEBSOCK_STR_ERROR_GENERAL);
        mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      }
      break;

    // Event | 'E' ; head(byte) , vscp_class(unsigned short) ,
    // vscp_type(unsigned
    //              short) , GUID(16*byte), data(0-487 bytes) |
    case 'E': {

      // Must be authorized to do this
      if ((NULL == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

        str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORISED, WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
        mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        syslog(LOG_ERR,
               "[Websocket ws1] User [%s] is not "
               "authorized.\n",
               pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

        return true;
      }

      // User must be allowed to send events
      if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

        str = vscp_str_format(("-;%d;%s"),
                              (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                              WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);

        mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        syslog(LOG_ERR,
               "[Websocket ws1] User [%s] is not "
               "allowed to send events.\n",
               pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

        return true; // We still leave channel open
      }

      // Point beyond initial info "E;"
      strWsPkt = vscp_str_right(strWsPkt, strWsPkt.length() - 2);
      vscpEventEx ex;

      try {
        if (vscp_convertStringToEventEx(&ex, strWsPkt)) {

          // If GUID is all null give it GUID of interface
          if (vscp_isGUIDEmpty(ex.GUID)) {
            pSession->m_pClientItem->m_guid.writeGUID(ex.GUID);
          }

          // Is this user allowed to send events
          if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);

            mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

            syslog(LOG_ERR,
                   "[Websocket ws1] User [%s] is not "
                   "allowed to send events.\n",
                   pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

            return true; // We still leave channel open
          }

          // Is user allowed to send CLASS1.PROTOCOL events
          if ((VSCP_CLASS1_PROTOCOL == ex.vscp_class) && (VSCP_CLASS2_LEVEL1_PROTOCOL == ex.vscp_class) &&
              !(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
            mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

            syslog(LOG_ERR,
                   "[Websocket ws1] User [%s] is not "
                   "authorised to send CLASS1.PROTOCOL events.\n",
                   pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

            return true;
          }

          // Is user allowed to send CLASS2.PROTOCOL events
          if ((VSCP_CLASS2_PROTOCOL == ex.vscp_class) &&
              !(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
            mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

            syslog(LOG_ERR,
                   "[Websocket ws1] User [%s] is not "
                   "authorised to send CLASS2.PROTOCOL events.\n",
                   pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

            return true;
          }

          // Is user allowed to send CLASS2.HLO events
          if ((VSCP_CLASS2_HLO == ex.vscp_class) &&
              !(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
            mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

            syslog(LOG_ERR,
                   "[Websocket ws1] User [%s] is not "
                   "authorised to send CLASS2.HLO events.\n",
                   pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

            return true;
          }

          // Check if this user is allowed to send this event
          if (!pSession->m_pClientItem->m_pUserItem->isUserAllowedToSendEvent(ex.vscp_class, ex.vscp_type)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);

            mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

            syslog(LOG_ERR,
                   "[websocket ws1] User [%s] is not allowed to "
                   "send event class=%d type=%d.",
                   pSession->m_pClientItem->m_pUserItem->getUserName().c_str(),
                   ex.vscp_class,
                   ex.vscp_type);

            return true; // Keep connection open
          }

          ex.obid = pSession->m_pClientItem->m_clientID;
          if (websock_sendevent(conn, pSession, &ex)) {
            mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;EVENT", 7, WEBSOCKET_OP_TEXT);
            if (__VSCP_DEBUG_WEBSOCKET_TX) {
              syslog(LOG_ERR, "[websocket ws1] Sent ws1 event %s", strWsPkt.c_str());
            }
          }
          else {
            str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_TX_BUFFER_FULL, WEBSOCK_STR_ERROR_TX_BUFFER_FULL);
            mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
          }
        }
      }
      catch (...) {
        syslog(LOG_ERR, "ws1: Exception occurred send event");
        str = vscp_str_format(("-;E;%d;%s"), (int) WEBSOCK_ERROR_GENERAL, WEBSOCK_STR_ERROR_GENERAL);
        mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      }

    } break;

    // Unknown command
    default:
      break;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////////
// ws1_command
//

int
websocketsrv::ws1_command(struct mg_connection *conn, std::string &strCmd)
{
  std::string str; // Worker string
  std::string strTok;

  // Check pointers
  if (NULL == conn) {
    return;
  }

  CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return;
  }

  if (__VSCP_DEBUG_WEBSOCKET) {
    syslog(LOG_ERR, "[Websocket ws1] Command = %s", strCmd.c_str());
  }

  std::deque<std::string> tokens;
  vscp_split(tokens, strCmd, ";");

  // Get command
  if (!tokens.empty()) {
    strTok = tokens.front();
    tokens.pop_front();
    vscp_trim(strTok);
    vscp_makeUpper(strTok);
  }
  else {
    std::string str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    return;
  }

  // ------------------------------------------------------------------------
  //                                NOOP
  //-------------------------------------------------------------------------

  if (vscp_startsWith(strTok, "NOOP")) {
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;NOOP", 6, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                               CHALLENGE
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "CHALLENGE")) {

    // Send authentication challenge
    if ((NULL == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      // Start authentication
      str = vscp_str_format(("+;AUTH0;%s"), pSession->m_sid);
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    }
  }

  // ------------------------------------------------------------------------
  //                                AUTH
  //-------------------------------------------------------------------------

  // AUTH;iv;aes128
  else if (vscp_startsWith(strTok, "AUTH")) {

    try {
      std::string str;
      std::string strUser;
      std::string strIV = tokens.front();
      tokens.pop_front();
      std::string strCrypto = tokens.front();
      tokens.pop_front();
      if (websock_authentication(conn, pSession, strIV, strCrypto)) {
        std::string userSettings;
        pSession->m_pClientItem->m_pUserItem->getAsString(userSettings);
        str = vscp_str_format(("+;AUTH1;%s"), (const char *) userSettings.c_str());
        mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      }
      else {

        str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORISED, WEBSOCK_STR_ERROR_NOT_AUTHORISED);
        mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
        pSession->m_pClientItem->bAuthenticated = false; // Authenticated
      }
    }
    catch (...) {
      syslog(LOG_ERR, "WS1: AUTH failed (syntax)");
      str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    }
  }

  // ------------------------------------------------------------------------
  //                                OPEN
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "OPEN")) {

    // Must be authorised to do this
    if ((NULL == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      str = vscp_str_format(("-;OPEN;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORISED, WEBSOCK_STR_ERROR_NOT_AUTHORISED);

      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      return; // We still leave channel open
    }

    pSession->m_pClientItem->m_bOpen = true;
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;OPEN", 6, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                                CLOSE
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "CLOSE")) {
    pSession->m_pClientItem->m_bOpen = false;
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;CLOSE", 7, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                             SETFILTER/SF
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "SETFILTER") || vscp_startsWith(strTok, "SF")) {

    unsigned char ifGUID[16];
    memset(ifGUID, 0, 16);

    // Must be authorized to do this
    if ((NULL == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORISED, WEBSOCK_STR_ERROR_NOT_AUTHORISED);

      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR, "[Websocket ws1] User/host not authorised to set a filter.");

      return; // We still leave channel open
    }

    // Check privilege
    if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SETFILTER)) {

      str = vscp_str_format(("-;SF;%d;%s"),
                            (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                            WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);

      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR,
             "[Websocket ws1] User [%s] not "
             "allowed to set a filter.\n",
             pSession->m_pClientItem->m_pUserItem->getUserName().c_str());
      return; // We still leave channel open
    }

    // Get filter
    if (!tokens.empty()) {

      strTok = tokens.front();
      tokens.pop_front();

      pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);
      if (!vscp_readFilterFromString(&pSession->m_pClientItem->m_filter, strTok)) {

        str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);

        mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
        return;
      }

      pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
    }
    else {

      str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);

      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      return;
    }

    // Get mask
    if (!tokens.empty()) {

      strTok = tokens.front();
      tokens.pop_front();

      pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);
      if (!vscp_readMaskFromString(&pSession->m_pClientItem->m_filter, strTok)) {

        str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);

        mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
        return;
      }

      pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
    }
    else {
      str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);

      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      return;
    }

    // Positive response
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;SF", 4, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                           CLRQ/CLRQUEUE
  //-------------------------------------------------------------------------

  // Clear the event queue
  else if (vscp_startsWith(strTok, "CLRQUEUE") || vscp_startsWith(strTok, "CLRQ")) {

    // Must be authorised to do this
    if ((NULL == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      str = vscp_str_format(("-;CLRQ;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORISED, WEBSOCK_STR_ERROR_NOT_AUTHORISED);

      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR, "[Websocket ws1] User/host not authorized to clear the queue.");

      return; // We still leave channel open
    }

    std::deque<vscpEvent *>::iterator it;
    pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);

    for (it = pSession->m_pClientItem->m_clientInputQueue.begin();
         it != pSession->m_pClientItem->m_clientInputQueue.end();
         ++it) {
      vscpEvent *pEvent = pSession->m_pClientItem->m_clientInputQueue.front();
      pSession->m_pClientItem->m_clientInputQueue.pop_front();
      vscp_deleteEvent_v2(&pEvent);
    }

    pSession->m_pClientItem->m_clientInputQueue.clear();
    pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);

    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;CLRQ", 6, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                              VERSION
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "VERSION")) {

    std::string strvalue;

    std::string strResult = ("+;VERSION;");
    strResult += VSCPD_DISPLAY_VERSION;
    strResult += (";");
    strResult += vscp_str_format(("%d.%d.%d.%d"),
                                 VSCPD_MAJOR_VERSION,
                                 VSCPD_MINOR_VERSION,
                                 VSCPD_RELEASE_VERSION,
                                 VSCPD_BUILD_VERSION);
    // Positive reply
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) strResult.c_str(), strResult.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                              COPYRIGHT
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "COPYRIGHT")) {

    std::string strvalue;

    std::string strResult = ("+;COPYRIGHT;");
    strResult += VSCPD_COPYRIGHT;

    // Positive reply
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) strResult.c_str(), strResult.length(), WEBSOCKET_OP_TEXT);
  }
}

// ----------------------------------------------------------------------------
//                                  WS2
// ----------------------------------------------------------------------------

////////////////////////////////////////////////////////////////////////////////
// ws2_connectHandler
//

// int
// websocketsrv::ws2_connectHandler(const struct mg_connection *conn, void *cbdata)
// {
//   struct mg_context *ctx = mg_get_context(conn);
//   int reject             = 1;

//   // Check pointers
//   if (NULL == conn) {
//     return 1;
//   }

//   if (NULL == ctx) {
//     return 1;
//   }

//   mg_lock_context(ctx);
//   websock_session *pSession = websock_new_session(conn);

//   if (NULL != pSession) {
//     reject = 0;
//   }

//   // This is a WS2 type connection
//   pSession->m_wstypes = WS_TYPE_2;

//   mg_unlock_context(ctx);

//   if (__VSCP_DEBUG_WEBSOCKET) {
//     syslog(LOG_ERR, "[Websocket ws2] WS2 Connection: client %s", (reject ? "rejected" : "accepted"));
//   }

//   return reject;
// }

////////////////////////////////////////////////////////////////////////////////
// ws2_closeHandler
//

// void
// websocketsrv::ws2_closeHandler(const struct mg_connection *conn, void *cbdata)
// {
//   struct mg_context *ctx    = mg_get_context(conn);
//   CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;

//   if (NULL == conn) {
//     return;
//   }
//   if (NULL == pSession) {
//     return;
//   }
//   if (pSession->m_conn != conn) {
//     return;
//   }
//   if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
//     return;
//   }

//   mg_lock_context(ctx);

//   // Record activity
//   pSession->lastActiveTime = time(NULL);

//   pSession->m_conn_state = WEBSOCK_CONN_STATE_NULL;
//   pSession->m_conn       = NULL;
//   m_clientList.removeClient(pSession->m_pClientItem);
//   pSession->m_pClientItem = NULL;

//   pthread_mutex_lock(&m_mutex_websocketSession);
//   m_websocketSessions.remove(pSession);
//   delete pSession;
//   pthread_mutex_unlock(&m_mutex_websocketSession);

//   mg_unlock_context(ctx);
// }

#define WS2_AUTH0_TEMPLATE                                                                                             \
  "{"                                                                                                                  \
  "    \"type\" : \"+\", "                                                                                             \
  "    \"args\" : [\"AUTH0\",\"%s\"]"                                                                                  \
  "}"

////////////////////////////////////////////////////////////////////////////////
// ws2_readyHandler
//

// void
// websocketsrv::ws2_readyHandler(struct mg_connection *conn, void *cbdata)
// {
//   CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;

//   // Check pointers
//   if (NULL == conn) {
//     return;
//   }

//   if (NULL == pSession) {
//     return;
//   }

//   if (pSession->m_conn != conn) {
//     return;
//   }

//   if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
//     return;
//   }

//   // Record activity
//   pSession->lastActiveTime = time(NULL);

//   // Start authentication
//   /* Auth0 response
//       {
//           "type" : "+"
//           "args" : ["AUTH0","%s"]
//       }
//   */
//   std::string str = vscp_str_format(WS2_AUTH0_TEMPLATE, pSession->m_sid);
//   mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

//   pSession->m_conn_state = WEBSOCK_CONN_STATE_DATA;
// }

////////////////////////////////////////////////////////////////////////////////
// ws2_dataHandler
//

int
websocketsrv::ws2_dataHandler(struct mg_connection *conn, int bits, char *data, size_t len, void *cbdata)
{
  std::string strWsPkt;

  // Check pointers
  if (NULL == conn) {
    return WEB_ERROR;
  }

  CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return WEB_ERROR;
  }

  if (pSession->m_conn_state < WEBSOCK_CONN_STATE_CONNECTED) {
    return WEB_ERROR;
  }

  // Record activity
  pSession->lastActiveTime = time(NULL);

  switch (((unsigned char) bits) & 0x0F) {

    case MG_WEBSOCKET_OPCODE_CONTINUATION:

      if (__VSCP_DEBUG_WEBSOCKET) {
        syslog(LOG_DEBUG, "Websocket WS2 - opcode = Continuation");
      }

      // Save and concatenate message
      pSession->m_strConcatenated += std::string(data, len);

      // if last process is
      if (1 & bits) {
        try {
          if (!ws2_message(conn, pSession, pSession->m_strConcatenated)) {
            return WEB_ERROR;
          }
        }
        catch (...) {
          syslog(LOG_ERR, "ws1: Exception occurred ws2_message concat");
        }
      }
      break;

    // https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
    case MG_WEBSOCKET_OPCODE_TEXT:

      if (__VSCP_DEBUG_WEBSOCKET) {
        syslog(LOG_DEBUG, "Websocket WS2 - opcode = Text [%s]", strWsPkt.c_str());
      }

      if (1 & bits) {
        try {
          strWsPkt = std::string(data, len);
          if (!ws2_message(conn, pSession, strWsPkt)) {
            return WEB_ERROR;
          }
        }
        catch (...) {
          syslog(LOG_ERR, "ws1: Exception occurred ws2_message");
        }
      }
      else {
        // Store first part
        pSession->m_strConcatenated = std::string(data, len);
      }
      break;

    case MG_WEBSOCKET_OPCODE_BINARY:
      if (__VSCP_DEBUG_WEBSOCKET) {
        syslog(LOG_DEBUG, "Websocket WS2 - opcode = BINARY");
      }
      break;

    case MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE:
      if (__VSCP_DEBUG_WEBSOCKET) {
        syslog(LOG_DEBUG, "Websocket WS2 - Connection close");
      }
      break;

    case MG_WEBSOCKET_OPCODE_PING:
      if (__VSCP_DEBUG_WEBSOCKET_PING) {
        syslog(LOG_DEBUG, "Websocket WS2 - Ping received/Pong sent,");
      }
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_PONG, data, len, WEBSOCKET_OP_TEXT);
      break;

    case MG_WEBSOCKET_OPCODE_PONG:
      if (__VSCP_DEBUG_WEBSOCKET_PING) {
        syslog(LOG_DEBUG, "Websocket WS2 - Pong received/Ping sent,");
      }
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_PING, data, len, WEBSOCKET_OP_TEXT);
      break;

    default:
      break;
  }

  return WEB_OK;
}

///////////////////////////////////////////////////////////////////////////////
// ws2_message
//

int
websocketsrv::ws2_message(struct mg_connection *conn, std::string &strWsPkt)
{
  w2msg msg;
  std::string str;
  json json_obj; // Command obj, event obj etc

  // Check pointers
  if (NULL == conn) {
    return false;
  }

  CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return false;
  }

  /*
  {
      "type": "event(E)|command(C)|response(+)|variable(V),
  }
  */
  try {
    json json_pkg = json::parse(strWsPkt.c_str());

    // "type": "event(E)|command(C)|response(+)|variable(V)
    if (json_pkg.find("type") != json_pkg.end()) {

      std::string str = json_pkg.at("type").get<std::string>();
      vscp_trim(str);
      vscp_makeUpper(str);

      // Command
      if (("COMMAND" == str) || ("CMD" == str) || ("C" == str)) {

        msg.m_type = MSG_TYPE_COMMAND;

        // Get command
        std::string strCmd = json_pkg.at("command").get<std::string>();
        vscp_trim(strCmd);
        vscp_makeUpper(strCmd);

        // Find args
        try {

          for (auto it = json_pkg.begin(); it != json_pkg.end(); ++it) {
            if ("args" == it.key()) {
              // str      = it.value();
              // json_obj = json::parse(str);
              return ws2_command(conn, pSession, strCmd, it.value());
            }
          }

          std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                            strCmd.c_str(),
                                            WEBSOCK_ERROR_PARSE_FORMAT,
                                            WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          // No arg found
          syslog(LOG_ERR, "Failed to parse ws2 websocket command object %s", strWsPkt.c_str());
          return false;
        }
        catch (...) {
          std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                            strCmd.c_str(),
                                            WEBSOCK_ERROR_PARSE_FORMAT,
                                            WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          syslog(LOG_ERR, "Failed to parse ws2 websocket command object %s", strWsPkt.c_str());

          return false;
        }
      }
      // Event
      else if (("EVENT" == str) || ("E" == str)) {
        msg.m_type = MSG_TYPE_EVENT;
        try {
          for (auto it = json_pkg.begin(); it != json_pkg.end(); ++it) {
            if ("event" == it.key()) {

              str = it.value().dump();

              // Client must be authorised to send events
              if ((NULL == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

                str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                      "EVENT",
                                      (int) WEBSOCK_ERROR_NOT_AUTHORISED,
                                      WEBSOCK_STR_ERROR_NOT_AUTHORISED);

                mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                syslog(LOG_ERR,
                       "[Websocket ws2] User [%s] is not "
                       "allowed to login.\n",
                       pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

                return false; // 'false' - Drop connection
              }

              vscpEventEx ex;
              if (vscp_convertJSONToEventEx(&ex, str)) {

                // If GUID is all null give it GUID of interface
                if (vscp_isGUIDEmpty(ex.GUID)) {
                  pSession->m_pClientItem->m_guid.writeGUID(ex.GUID);
                }

                // Is this user allowed to send events
                if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  syslog(LOG_ERR,
                         "[Websocket ws2] User [%s] is not "
                         "allowed to send events.\n",
                         pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS1.PROTOCOL
                // events
                if ((VSCP_CLASS1_PROTOCOL == ex.vscp_class) && (VSCP_CLASS2_LEVEL1_PROTOCOL == ex.vscp_class) &&
                    !(pSession->m_pClientItem->m_pUserItem->getUserRights() &
                      VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  syslog(LOG_ERR,
                         "[Websocket ws2] User [%s] is not "
                         "authorised to send CLASS1.PROTOCOL "
                         "events.\n",
                         pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS2.PROTOCOL
                // events
                if ((VSCP_CLASS2_PROTOCOL == ex.vscp_class) && !(pSession->m_pClientItem->m_pUserItem->getUserRights() &
                                                                 VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  syslog(LOG_ERR,
                         "[Websocket ws2] User [%s] is not "
                         "authorized to send CLASS2.PROTOCOL "
                         "events.\n",
                         pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS2.HLO events
                if ((VSCP_CLASS2_HLO == ex.vscp_class) &&
                    !(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  syslog(LOG_ERR,
                         "[Websocket ws2] User [%s] is not "
                         "authorised to send CLASS2.HLO "
                         "events.\n",
                         pSession->m_pClientItem->m_pUserItem->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Check if this user is allowed to send this
                // event
                if (!pSession->m_pClientItem->m_pUserItem->isUserAllowedToSendEvent(ex.vscp_class, ex.vscp_type)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  syslog(LOG_ERR,
                         "websocket] User [%s] is not allowed to "
                         "send event class=%d type=%d.",
                         pSession->m_pClientItem->m_pUserItem->getUserName().c_str(),
                         ex.vscp_class,
                         ex.vscp_type);

                  return true; // 'true' leave connection open
                }

                ex.obid = pSession->m_pClientItem->m_clientID;
                if (websock_sendevent(conn, pSession, &ex)) {

                  str = vscp_str_format(WS2_POSITIVE_RESPONSE, "EVENT", "null");
                  mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  if (__VSCP_DEBUG_WEBSOCKET_TX) {
                    syslog(LOG_ERR, "Sent ws2 event %s", strWsPkt.c_str());
                  }
                }
                else {

                  str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        "EVENT",
                                        (int) WEBSOCK_ERROR_TX_BUFFER_FULL,
                                        WEBSOCK_STR_ERROR_TX_BUFFER_FULL);
                  mg_ws_send(conn,
                             MG_WEBSOCKET_OPCODE_TEXT,
                             (const char *) str.c_str(),
                             str.length(),
                             WEBSOCKET_OP_TEXT);
                  syslog(LOG_ERR, "Transmission buffer is full %s", strWsPkt.c_str());

                  return true; // 'true' leave connection open
                }
              }
            }
          }
        }
        catch (...) {
          std::string str =
            vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_PARSE_FORMAT, WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          syslog(LOG_ERR, "Failed to parse ws2 websocket event object %s", strWsPkt.c_str());

          return true; // 'true' leave connection open
        }
      }
      // Positive response
      else if ("+" == str) {
        msg.m_type = MSG_TYPE_RESPONSE_POSITIVE;
        try {
          for (auto it = json_pkg.begin(); it != json_pkg.end(); ++it) {
            if ("response" == it.key()) {
              str      = it.value();
              json_obj = json::parse(str);
              break;
            }
          }
        }
        catch (...) {
          std::string str =
            vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_PARSE_FORMAT, WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          syslog(LOG_ERR, "Failed to parse ws2 websocket + response object %s", strWsPkt.c_str());
          return true; // 'true' leave connection open
        }
      }
      // Negative response
      else if ("-" == str) {
        msg.m_type = MSG_TYPE_RESPONSE_NEGATIVE;
        try {
          for (auto it = json_pkg.begin(); it != json_pkg.end(); ++it) {
            if ("response" == it.key()) {
              str      = it.value();
              json_obj = json::parse(str);
              break;
            }
          }
        }
        catch (...) {
          std::string str =
            vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_PARSE_FORMAT, WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          syslog(LOG_ERR, "Failed to parse ws2 websocket - response object %s", strWsPkt.c_str());
          return true; // 'true' leave connection open
        }
      }
      // Changed variable
      else if ("VARIABLE" == str) {
        msg.m_type = MSG_TYPE_VARIABLE;
        try {
          for (auto it = json_pkg.begin(); it != json_pkg.end(); ++it) {
            if ("variable" == it.key()) {
              str      = it.value();
              json_obj = json::parse(str);
              break;
            }
          }
        }
        catch (...) {
          std::string str =
            vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_PARSE_FORMAT, WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          syslog(LOG_ERR, "Failed to parse ws2 websocket variable object %s", strWsPkt.c_str());
          return true; // 'true' leave connection open
        }
      }
      else {
        std::string str =
          vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_UNKNOWN_TYPE, WEBSOCK_STR_ERROR_UNKNOWN_TYPE);
        mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        // This is a type we do not recognize
        syslog(LOG_ERR, "Unknown ws2 websocket type %s", strWsPkt.c_str());
        return true; // 'true' leave connection open
      }
    }
  }
  catch (...) {
    std::string str =
      vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_UNKNOWN_TYPE, WEBSOCK_STR_ERROR_UNKNOWN_TYPE);
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

    syslog(LOG_ERR, "Failed to parse ws2 websocket command %s", strWsPkt.c_str());
    return true; // 'true' leave connection open
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////////
// ws2_command
//

int
websocketsrv::ws2_command(struct mg_connection *conn, std::string &strCmd, json &jsonObj)
{
  // Check pointers
  if (NULL == conn) {
    return false;
  }

  CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return false;
  }

  if (__VSCP_DEBUG_WEBSOCKET) {
    syslog(LOG_DEBUG, "[Websocket ws2] Command = %s", strCmd.c_str());
  }

  // Get arguments
  std::map<std::string, std::string> argmap;
  try {
    for (auto it = jsonObj.begin(); it != jsonObj.end(); ++it) {
      if (it.value().is_string()) {
        argmap[it.key()] = it.value();
      }
    }
  }
  catch (...) {
    std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                      "SETFILTER",
                                      (int) WEBSOCK_ERROR_PARSE_FORMAT,
                                      WEBSOCK_STR_ERROR_PARSE_FORMAT);
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

    syslog(LOG_ERR, "[Websocket ws2] SETFILTER parse error = %s", jsonObj.dump().c_str());

    return false;
  }

  // ------------------------------------------------------------------------
  //                                NOOP
  //-------------------------------------------------------------------------

  if ("NOOP" == strCmd) {

    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, "NOOP", "null");
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                               CHALLENGE
  //-------------------------------------------------------------------------

  else if ("CHALLENGE" == strCmd) {

    // Send authentication challenge
    if ((NULL == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      // Start authentication
      std::string strSessionId = vscp_str_format("{\"sid\": \"%s\"}", pSession->m_sid);
      std::string str          = vscp_str_format(WS2_POSITIVE_RESPONSE, "CHALLENGE", strSessionId);
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    }
  }

  // ------------------------------------------------------------------------
  //                                AUTH
  //-------------------------------------------------------------------------

  // AUTH;iv;aes128
  else if ("AUTH" == strCmd) {

    std::string str;
    std::string strUser;
    std::string strIV     = argmap["iv"];
    std::string strCrypto = argmap["crypto"];
    if (websock_authentication(conn, pSession, strIV, strCrypto)) {
      std::string userSettings;
      pSession->m_pClientItem->m_pUserItem->getAsString(userSettings);
      str = vscp_str_format(WS2_POSITIVE_RESPONSE, "AUTH", "null");
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    }
    else {

      str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                            "AUTH",
                            (int) WEBSOCK_ERROR_NOT_AUTHORISED,
                            WEBSOCK_STR_ERROR_NOT_AUTHORISED);
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      pSession->m_pClientItem->bAuthenticated = false; // Authenticated
    }
  }

  // ------------------------------------------------------------------------
  //                                OPEN
  //-------------------------------------------------------------------------

  else if ("OPEN" == strCmd) {

    // Must be authorized to do this
    if ((NULL == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        "OPEN",
                                        (int) WEBSOCK_ERROR_NOT_AUTHORISED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORISED);
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      return false; // We still leave channel open
    }

    pSession->m_pClientItem->m_bOpen = true;
    std::string str                  = vscp_str_format(WS2_POSITIVE_RESPONSE, "OPEN", "null");
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                                CLOSE
  //-------------------------------------------------------------------------

  else if ("CLOSE" == strCmd) {
    pSession->m_pClientItem->m_bOpen = false;
    std::string str                  = vscp_str_format(WS2_POSITIVE_RESPONSE, "CLOSE", "null");
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                             SETFILTER/SF
  //-------------------------------------------------------------------------

  else if (("SETFILTER" == strCmd) || ("SF" == strCmd)) {

    std::string strFilter;
    unsigned char ifGUID[16];
    memset(ifGUID, 0, 16);

    // Must be authorized to do this
    if ((NULL == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_AUTHORISED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORISED);
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR, "[Websocket w2] User/host is not authorised to set a filter.");

      return false; // We still leave channel open
    }

    // Check privilege
    if (!(pSession->m_pClientItem->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SETFILTER)) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                        WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR,
             "[Websocket w2] User [%s] is not "
             "allowed to set a filter.\n",
             pSession->m_pClientItem->m_pUserItem->getUserName().c_str());
      return false; // We still leave channel open
    }

    // Get filter
    if (!argmap.empty()) {

      strFilter = jsonObj.dump();

      pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);
      if (!vscp_readFilterMaskFromJSON(&pSession->m_pClientItem->m_filter, strFilter)) {

        std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                          strCmd.c_str(),
                                          (int) WEBSOCK_ERROR_SYNTAX_ERROR,
                                          WEBSOCK_STR_ERROR_SYNTAX_ERROR);
        mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        syslog(LOG_ERR, "[Websocket w2] Set filter syntax error. [%s]", strFilter.c_str());

        pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
        return false;
      }

      pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);
    }
    else {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_SYNTAX_ERROR,
                                        WEBSOCK_STR_ERROR_SYNTAX_ERROR);
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR, "[Websocket w2] Set filter syntax error. [%s]", strFilter.c_str());

      return false;
    }

    // Positive response
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), "null");
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                           CLRQ/CLRQUEUE
  //-------------------------------------------------------------------------

  // Clear the event queue
  else if (("CLRQUEUE" == strCmd) || ("CLRQ" == strCmd)) {

    // Must be authorised to do this
    if ((NULL == pSession->m_pClientItem) || !pSession->m_pClientItem->bAuthenticated) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_AUTHORISED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORISED);
      mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR, "[Websocket w2] User/host is not authorised to clear the queue.");

      return false; // We still leave channel open
    }

    std::deque<vscpEvent *>::iterator it;
    pthread_mutex_lock(&pSession->m_pClientItem->m_mutexClientInputQueue);

    for (it = pSession->m_pClientItem->m_clientInputQueue.begin();
         it != pSession->m_pClientItem->m_clientInputQueue.end();
         ++it) {
      vscpEvent *pEvent = pSession->m_pClientItem->m_clientInputQueue.front();
      pSession->m_pClientItem->m_clientInputQueue.pop_front();
      vscp_deleteEvent_v2(&pEvent);
    }

    pSession->m_pClientItem->m_clientInputQueue.clear();
    pthread_mutex_unlock(&pSession->m_pClientItem->m_mutexClientInputQueue);

    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), "null");
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                              VERSION
  //-------------------------------------------------------------------------

  else if (("VERSION" == strCmd) || ("VER" == strCmd)) {

    // std::string strvalue;
    std::string strResult;
    strResult = vscp_str_format("{ \"version\" : \"%d.%d.%d-%d\" }",
                                VSCPD_MAJOR_VERSION,
                                VSCPD_MINOR_VERSION,
                                VSCPD_RELEASE_VERSION,
                                VSCPD_BUILD_VERSION);
    // Positive reply
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), strResult.c_str());
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                              COPYRIGHT
  //-------------------------------------------------------------------------

  else if ("COPYRIGHT" == strCmd) {

    std::string strvalue;

    std::string strResult = ("{ \"copyright\" : \"");
    strResult += VSCPD_COPYRIGHT;
    strResult += "\" }";

    // Positive reply
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), strResult.c_str());
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }
  else {
    std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                      strCmd,
                                      (int) WEBSOCK_ERROR_UNKNOWN_COMMAND,
                                      WEBSOCK_STR_ERROR_UNKNOWN_COMMAND);
    syslog(LOG_ERR, "[Websocket w2] Unknown command [%s].", strCmd.c_str());

    return false;
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////////
// ws2_xcommand
//

int
websocketsrv::ws2_xcommand(struct mg_connection *conn, std::string &strCmd)
{
  std::string str; // Worker string
  std::string strTok;

  // Check pointers
  if (NULL == conn) {
    return;
  }

  CWebsockSession *pSession = (CWebsockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return;
  }

  if (__VSCP_DEBUG_WEBSOCKET) {
    syslog(LOG_ERR, "[Websocket ws2] Command = %s", strCmd.c_str());
  }

  std::deque<std::string> tokens;
  vscp_split(tokens, strCmd, ";");

  // Get command
  if (!tokens.empty()) {
    strTok = tokens.front();
    tokens.pop_front();
    vscp_trim(strTok);
    vscp_makeUpper(strTok);
  }
  else {
    std::string str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    return;
  }

  // ------------------------------------------------------------------------
  //                                NOOP
  //-------------------------------------------------------------------------

  if (vscp_startsWith(strTok, "NOOP")) {
    mg_ws_send(conn, MG_WEBSOCKET_OPCODE_TEXT, "+;NOOP", 6, WEBSOCKET_OP_TEXT);
  }
}

///////////////////////////////////////////////////////////////////////////////
// srv_event_handler
//
// Timer function - recreate client connection if it is closed
//

static void
timer_fn(void *arg)
{
  struct mg_mgr *mgr = (struct mg_mgr *) arg;
  if (c_res.c == NULL) {
    c_res.i = 0;
    c_res.c = mg_connect(mgr, s_conn, cfn, &c_res);
    MG_INFO(("CLIENT %s", c_res.c ? "connecting" : "failed"));
  }
}

///////////////////////////////////////////////////////////////////////////////
// srv_event_handler
//
// SERVER event handler
// This RESTful server implements the following endpoints:
//   /ws1 - upgrade to Websocket, and implement ws1 server
//   /ws2 - upgrade to Websocket, and implement ws2 server
//   /rest - respond with JSON string {"result": 123}
//   any other URI serves static files from s_web_root

static void
server_event_handler(struct mg_connection *con, int mgev, void *ev_data)
{
  // Check pointers
  if (NULL == conn) {
    syslog(LOG_ERR, "Communication context is NULL.");
    return;
  }

  if (NULL == ev_data) {
    syslog(LOG_ERR, "server_event_handler: ev_data is NULL.");
    return;
  }

  struct mg_tls_opts *tls_opts = NULL;
  struct mg_str s_ca_path      = mg_str(s_ca_file);
  struct mg_str s_cert_path    = mg_str(s_cert_file);
  struct mg_str s_key_path     = mg_str(s_key_file);

  websocketsrv *pWebSockSrv = (websocketsrv *) mg_get_user_connection_data(con);
  if (NULL == pWebSockSrv) {
    syslog(LOG_ERR, "server_event_handler: Invalid websocketsrv pointer.");
    return;
  }

  if (mgev == MG_EV_OPEN) {
    con->is_hexdumping = 1;
  }
  else if (c->is_tls && mgev == MG_EV_ACCEPT) {
    struct mg_str ca        = mg_file_read(&mg_fs_posix, s_ca_path);
    struct mg_str cert      = mg_file_read(&mg_fs_posix, s_cert_path);
    struct mg_str key       = mg_file_read(&mg_fs_posix, s_key_path);
    struct mg_tls_opts opts = { .ca = ca, .cert = cert, .key = key };
    mg_tls_init(con, &opts);
  }
  else if (mgev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    if (mg_match(hm->uri, mg_str("/ws1"), NULL)) {
      // Upgrade to websocket (ws1 protocol). From now on, a connection is a full-duplex
      // Websocket connection, which will receive MG_EV_WS_MSG events.
      mg_ws_upgrade(con, hm, NULL);

      CWebsockSession *pSession = new CWebsockSession();
      if (NULL == pSession) {
        syslog(LOG_ERR, "server_event_handler: Failed to create CWebsockSession instance.");
        mg_http_reply(con, 500, "", "Internal Server Error\n");
        return;
      }
      pSession->m_wstypes = WS_TYPE_1;
      conn->pfn_data      = pSession; // Set session pointer in connection

      // Send AUTH start message
      ws1_readyHandler(conn, pSession);
    }
    else if (mg_match(hm->uri, mg_str("/ws2"), NULL)) {
      // Upgrade to websocket (ws2 protocol). From now on, a connection is a full-duplex
      // Websocket connection, which will receive MG_EV_WS_MSG events.
      mg_ws_upgrade(con, hm, NULL);

      CWebsockSession *pSession = new CWebsockSession();
      if (NULL == pSession) {
        syslog(LOG_ERR, "server_event_handler: Failed to create CWebsockSession instance.");
        mg_http_reply(con, 500, "", "Internal Server Error\n");
        return;
      }
      pSession->m_wstypes = WS_TYPE_2;
      conn->pfn_data      = pSession; // Set session pointer in connection

      // Send AUTH start message
      ws2_readyHandler(conn, pSession);
    }
    else if (mg_match(hm->uri, mg_str("/rest"), NULL)) {
      // Serve REST response
      mg_http_reply(con, 200, "", "{\"result\": %d}\n", 123);
    }
    else {
      // Serve static files
      struct mg_http_serve_opts opts = { .root_dir = s_web_root };
      mg_http_serve_dir(con, ev_data, &opts);
    }
  }
  else if (mgev == MG_EV_WS_MSG) {
    // Got websocket frame. Received data is wm->data. Echo it back!
    struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
    mg_ws_send(con, wm->data.buf, wm->data.len, WEBSOCKET_OP_TEXT, WEBSOCKET_OP_TEXT);
  }
  else if (mgev == MG_EV_WAKEUP) {
    struct mg_str *data = (struct mg_str *) ev_data;
    // Broadcast message to all connected websocket clients,
    // except the one that sent it.
    if (data == NULL || data->len == 0) {
      syslog(LOG_ERR, "server_event_handler: No data to send.");
      return;
    }
    syslog(LOG_INFO, "Broadcasting message: %.*s", (int) data->len, data->buf);

    // Iterate over all connections in the manager
    // and send the message to all websocket connections.
    // Note: This is a simple broadcast, you may want to implement
    // more sophisticated logic to filter which connections should receive the message.
    // This is a simple example, in a real application you might want to
    // implement more sophisticated logic to filter which connections should receive the message.
    // For example, you might want to send only to connections that have a specific label or
    // that are subscribed to a specific topic.

    // Traverse over all connections
    for (struct mg_connection *wc = con->mgr->conns; wc != NULL; wc = wc->next) {
      // Send to all other connections not to self
      if ((wc->id != con->id) && wc->is_websocket) {
        mg_ws_send(wc, data->buf, data->len, WEBSOCKET_OP_TEXT, WEBSOCKET_OP_TEXT);
      }
    }
    else if (mgev == MG_EV_CLOSE)
    {
      // Connection is closed, free resources
      if (con->is_tls) {
        mg_tls_free(con);
      }

      if (nullptr != conn->pfn_data) {
        // Free the session data
        CWebsockSession *pSession = (CWebsockSession *) con->pfn_data;
        delete pSession;
        con->pfn_data = NULL; // Clear pointer to avoid dangling pointer
      }

      syslog(LOG_INFO, "Connection closed: %s", con->label);
    }
    else if (mgev == MG_EV_TIMER)
    {
      // Timer event, do nothing
    }
    else
    {
      syslog(LOG_ERR, "Unhandled event %d", mgev);
    }
  }
}

///////////////////////////////////////////////////////////////////////////////
// websockListenThread
//

static void *
websockListenThread(void *pData)
{
  websocketsrv *pWebsockSrv = (websocketsrv *) pData;
  if (NULL == pWebsockSrv) {
    syslog(LOG_ERR, "websockListenThread: Invalid websocketsrv pointer.");
    return NULL;
  }

  struct mg_mgr mgr; // Event manager
  mg_mgr_init(&mgr); // Initialise event manager
  printf("Starting WS listener on %s/websocket\n", pWebSockSrv->getUrl().c_str());

  // Create HTTP listener
  mg_http_listen(&mgr, pWebSockSrv->getUrl().c_str(), server_event_handler, NULL);

  while (!pWebsockSrv->m_bQuit) {
    mg_mgr_poll(&mgr, 100); // Poll for events
  }

  mg_mgr_free(&mgr);
  return 0;
}