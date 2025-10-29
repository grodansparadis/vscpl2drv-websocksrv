// websocket.h:
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

#if !defined(VSCP_WEBSOCKET_SRV_H__INCLUDED_)
#define VSCP_WEBSOCKET_SRV_H__INCLUDED_

#ifdef WIN32
#include "StdAfx.h"
#endif

#include <vector>
#include <string>
#include <ctime>
#include <map>
#include <list>

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#if WIN32
#else
#include <syslog.h>
#include <unistd.h>
#endif
#include <time.h>

#include <userlist.h>
#include <guid.h>

#include <mongoose.h>
#include <vscp.h>

#include <nlohmann/json.hpp> // Needs C++11  -std=c++11

#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"

// https://github.com/nlohmann/json
using json = nlohmann::json;

// Maximum number of events in a client queue
const uint16_t MAX_ITEMS_IN_QUEUE = 32000;

#define DRIVER_COPYRIGHT "Copyright © 2000-2025 Ake Hedman, the VSCP Project, https://www.vscp.org"

// for convenience
using json = nlohmann::json;

//******************************************************************************
//                                WEBSOCKETS
//******************************************************************************

// websocket types
#define WEBSOCKET_SUBYPE_STANDARD "vscp-std"  // Original format (ws1)
#define WEBSOCKET_SUBTYPE_JSON    "vscp-json" // JSON format (ws2)

// This is the time it takes for an expired websocket session to be
// removed by the system.
#define WEBSOCKET_EXPIRE_TIME (2 * 60)

// Authentication states
enum {
  WEBSOCK_CONN_STATE_NULL = 0,      // Not connected
  WEBSOCK_CONN_STATE_CONNECTED,     // Connected
  WEBSOCK_CONN_STATE_AUTHENTICATED, // Authenticated
  WEBSOCK_CONN_STATE_DATA
}; // Data transfer

enum {
  WEBSOCK_ERROR_NO_ERROR                  = 0,  // Everything is OK.
  WEBSOCK_ERROR_SYNTAX_ERROR              = 1,  // Syntax error.
  WEBSOCK_ERROR_UNKNOWN_COMMAND           = 2,  // Unknown command.
  WEBSOCK_ERROR_TX_BUFFER_FULL            = 3,  // Transmit buffer full.
  WEBSOCK_ERROR_MEMORY_ALLOCATION         = 4,  // Problem allocating memory.
  WEBSOCK_ERROR_NOT_AUTHORISED            = 5,  // Not authorised.
  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT = 6,  // Not authorised to send events.
  WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT    = 7,  // Not allowed to do that.
  WEBSOCK_ERROR_PARSE_FORMAT              = 8,  // Parse error, invalid format.
  WEBSOCK_ERROR_UNKNOWN_TYPE              = 9,  // Unkown object type
  WEBSOCK_ERROR_GENERAL                   = 10, // General errors and exceptions
};

#define WEBSOCK_STR_ERROR_NO_ERROR                  "Everything is OK."
#define WEBSOCK_STR_ERROR_SYNTAX_ERROR              "Syntax error."
#define WEBSOCK_STR_ERROR_UNKNOWN_COMMAND           "Unknown command."
#define WEBSOCK_STR_ERROR_TX_BUFFER_FULL            "Transmit buffer full."
#define WEBSOCK_STR_ERROR_MEMORY_ALLOCATION         "Having problems to allocate memory."
#define WEBSOCK_STR_ERROR_NOT_AUTHORISED            "Not authorised."
#define WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_SEND_EVENT "Not allowed to send event."
#define WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT    "Not allowed to do that (check privileges)"
#define WEBSOCK_STR_ERROR_PARSE_FORMAT              "Parse error, invalid format."
#define WEBSOCK_STR_ERROR_UNKNOWN_TYPE              "Unknown type, only know 'COMMAND' and 'EVENT'."
#define WEBSOCK_STR_ERROR_GENERAL                   "Exception or other general error."

#define WEBSOCKET_MAINCODE_POSITIVE "+"
#define WEBSOCKET_MAINCODE_NEGATIVE "-"

#define WEBSOCKET_MAINCODE_COMMAND  "C"
#define WEBSOCKET_MAINCODE_EVENT    "E"
#define WEBSOCKET_MAINCODE_VARIABLE "V"

#define WEBSOCKET_SUBCODE_VARIABLE_CHANGED "C"
#define WEBSOCKET_SUBCODE_VARIABLE_CREATED "N"
#define WEBSOCKET_SUBCODE_VARIABLE_DELETED "D"

#define WS_TYPE_1 1
#define WS_TYPE_2 2

///////////////////////////////////////////////////////////////////////////////
// Class for websocket session
///////////////////////////////////////////////////////////////////////////////

class CWebSockSession {

public:
  CWebSockSession(void);
  ~CWebSockSession(void);

  /*!
    @brief Start the websocket session
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int start(void);

  /*!
    @brief Stop the websocket session
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int stop(void);

  /*!
    @brief Add event to the input queue
    @param pEvent Pointer to the VSCP event to add to the input queue
    @return VSCP_ERROR_SUCCESS on success, otherwise VSCP error code.
  */
  int addToInputQueue(const vscpEvent *pEvent);

  /*!
    @brief Generate a random session ID (SID)
  */
  void generateSid(void);

  // * * * Getters/Setters

  void setWebsocketKey(const uint8_t *pKey)
  {
    if (pKey) {
      memcpy(m_websocket_key, pKey, sizeof(m_websocket_key));
    }
    else {
      memset(m_websocket_key, 0, sizeof(m_websocket_key));
    }
  }

  /*!
    @brief Get the unique ID for this session
    @return Pointer to the unique ID for this session
  */
  const uint8_t *getWebsocketKey(void) { return m_websocket_key; }

  // Getters/setters

  /*!
    @brief Get the session ID (SID) for this session
    @return Pointer to the session ID for this session
  */
  const char *getSid(void) { return m_sid; }

  /*!
   @brief Set the session ID (SID) for this session
   @param pSid Null terminated string sid (max 32 characters)
  */
  void setSid(const char *pSid)
  {
    if (pSid) {
      strncpy(m_sid, pSid, sizeof(m_sid));
      m_sid[sizeof(m_sid) - 1] = 0;
    }
    else {
      memset(m_sid, 0, sizeof(m_sid));
    }
  }

  /*!
   @brief Get the encryption key for this session
   @return Pointer to the encryption key for this session
  */
  const uint8_t *getKey(void) { return m_key; }

  /*!
   @brief Set the encryption key for this session
   @param pKey 16 byte encryption key
  */
  void setKey(const uint8_t *pKey)
  {
    if (pKey) {
      memcpy(m_key, pKey, sizeof(m_key));
    }
    else {
      memset(m_key, 0, sizeof(m_key));
    }
  }

  int getVersion(void) { return m_version; }
  void setVersion(int version) { m_version = version; }

  uint8_t getWsType(void) { return m_wstype; }
  void setWsType(uint8_t wstype) { m_wstype = wstype; }

  int getConnState(void) { return m_conn_state; }
  void setConnState(int state) { m_conn_state = state; }

  // Get last active time
  time_t getLastActiveTime(void) { return lastActiveTime; }
  void setLastActiveTime(time_t t) { lastActiveTime = t; }

  std::string getConcatenatedString(void) { return m_strConcatenated; }
  void clearConcatenatedString(void) { m_strConcatenated.clear(); }
  void setConcatenatedString(const std::string &str) { m_strConcatenated = str; }
  void addConcatenatedString(struct mg_str &msg)
  {
    if (msg.buf && msg.len > 0) {
      m_strConcatenated.append(msg.buf, msg.len);
    }
  };

  struct mg_connection *getConnection() { return m_conn; };
  void setConnection(struct mg_connection *conn) { m_conn = conn; };

  bool isOpen(void) { return m_bOpen; };
  void setOpen(bool bOpen) { m_bOpen = bOpen; };

  vscpEventFilter *getFilter(void) { return &m_filter; };
  void setFilter(const vscpEventFilter *pfilter) { vscp_copyVSCPFilter(&m_filter, pfilter); };

  cguid *getGuid() { return &m_guid; };
  void setGuid(const cguid &guid) { m_guid = guid; };

  CUserItem *getUserItem(void) { return m_pUserItem; };
  void setUserItem(CUserItem *puser) { m_pUserItem = puser; };

  bool isAuthenticated(void) { return m_bAuthenticated; };
  void setAuthenticated(bool bAuthenticated) { m_bAuthenticated = bAuthenticated; };

public:
  // Input Queue (events directed to this client)
  std::deque<vscpEvent *> m_inputQueue;

  // Semaphore to signal that an event has been received
  sem_t m_semInputQueue;

  // Mutex handle that is used for sharing of the client object
  pthread_mutex_t m_mutexInputQueue;

  uint16_t m_maxInputQueue; // Max size of input queue per client

private:
  // ws type (0 = not set, 1 = ws1, 2 = ws2)
  uint8_t m_wstype;

  // Connection state (see enums above)
  int m_conn_state;

  // Encryption key
  uint8_t m_key[16];

  // Unique ID for this session.
  // 16 byte iv (SID) for this session
  char m_sid[33];

  // Websocket protocol version saved from header
  int m_version; // Sec-WebSocket-Version

  // Websocket key (WS_KEY) for this session
  uint8_t m_websocket_key[24];

  // Time when this session was last active.
  time_t lastActiveTime;

  // Concatenated message receive
  std::string m_strConcatenated;

  // Client item

  // Flag for open/closed channel
  bool m_bOpen;

  // Filter/mask for VSCP
  vscpEventFilter m_filter;

  /*!
      Interface GUID

      The GUID for a client have the following form MSB -> LSB

      0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFD ip-address ip-address ip-address
      ip-address Client-ID Client-ID 0 0

      ip-address ver 4 interface IP address
      Client-ID mapped id for this client

      This is the default address and it can be changed by the client
     application

  */
  cguid m_guid;

  bool m_bAuthenticated; // True if authenticated

  // User item
  CUserItem *m_pUserItem;

  struct mg_connection *m_conn; // Mongoose connection
};

#define WS2_COMMAND                                                                                                    \
  "{"                                                                                                                  \
  " \"type\" : \"CMD\", "                                                                                              \
  " \"command\" : \"%s\", "                                                                                            \
  " \"args\" : %s"                                                                                                     \
  "}"

#define WS2_EVENT                                                                                                      \
  "{"                                                                                                                  \
  " \"type\" : \"EVENT\", "                                                                                            \
  " \"event\" : "                                                                                                      \
  " %s "                                                                                                               \
  "}"

#define WS2_POSITIVE_RESPONSE                                                                                          \
  "{"                                                                                                                  \
  " \"type\" : \"+\", "                                                                                                \
  " \"command\" : \"%s\", "                                                                                            \
  " \"args\" : %s"                                                                                                     \
  "}"

#define WS2_NEGATIVE_RESPONSE                                                                                          \
  "{"                                                                                                                  \
  " \"type\" : \"-\", "                                                                                                \
  " \"command\" : \"%s\", "                                                                                            \
  " \"errcode\" : %d, "                                                                                                \
  " \"errstr\" : \"%s\" "                                                                                              \
  "}"

#define WS2_VARIABLE                                                                                                   \
  "{"                                                                                                                  \
  " \"type\" : \"VARIABLE\", "                                                                                         \
  " \"variable\" : "                                                                                                   \
  " %s "                                                                                                               \
  "}"

const int MSG_TYPE_COMMAND           = 0; // Built in command
const int MSG_TYPE_XCOMMAND          = 1; // Add on command
const int MSG_TYPE_EVENT             = 2; // Event
const int MSG_TYPE_RESPONSE_POSITIVE = 3; // Positive reply
const int MSG_TYPE_RESPONSE_NEGATIVE = 4; // Negative reply
const int MSG_TYPE_VARIABLE          = 5; // Changed variable

///////////////////////////////////////////////////////////////////////////////
// Class for w2 message
///////////////////////////////////////////////////////////////////////////////

class w2msg {
public:
  w2msg(void);
  ~w2msg(void);

  /*
    Event (E) / Command (C) / Response (+/-) / Variable (V)
  */
  int m_type;

  /*
      Command/Response/Variable arguments
  */
  std::map<std::string, std::string> m_arguments;

  /*
      Holder for Event
  */
  vscpEventEx m_ex;
};

// Public functions
// void
// websock_post_incomingEvents(void);

///////////////////////////////////////////////////////////////////////////////
// Class for websocket server
// This class is used to handle the websocket server
// It is a singleton class that can be used to handle multiple websocket
// connections. Both ws1 and ws2 is supported.
///////////////////////////////////////////////////////////////////////////////

class CWebSockSrv {

public:
  CWebSockSrv(void);
  ~CWebSockSrv(void);

  /*!
    @brief Initialize the websocket server
    @param url URL for the websocket server (ws:// or wss://)
    @param web_root Web root for the websocket server
    @param ca_path Path to CA certificate for TLS
    @param cert_path Path to server certificate for TLS
    @param key_path Path to server key for TLS
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */

  /*!
    @brief Load configuration from file
    @param path Path to configuration file
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
            VSCP_ERROR_PARSING if there is a parsing error.
  */
  int doLoadConfig(std::string &path);

  /*!
    @brief Save configuration to file
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int doSaveConfig(void);

  /*!
    @brief Start websocket server
    @param
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int start(void);

  /*!
    @brief  Stop websocket server
    @param
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int stop(void);

  /*!
    @brief Restart websocket server
    @param
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int restart(void);

  // Getters/setters for URL, web root, CA path, cert path and key path
  std::string getUrl(void) const { return m_url; }
  void setUrl(const std::string &url) { m_url = url; }

  // get ws1 URL
  std::string getWs1Url(void) const { return m_url_ws1; }
  void setWs1Url(const std::string &url) { m_url_ws1 = url; }

  // is ws1 enabled
  bool isEnableWS1(void) const { return m_bEnableWS1; }
  void setEnableWS1(bool bEnable) { m_bEnableWS1 = bEnable; }

  // get ws2 URL
  std::string getWs2Url(void) const { return m_url_ws2; }
  void setWs2Url(const std::string &url) { m_url_ws2 = url; }

  // is ws2 enabled
  bool isEnableWS2(void) const { return m_bEnableWS2; }
  void setEnableWS2(bool bEnable) { m_bEnableWS2 = bEnable; }

  // get rest URL
  std::string getRestUrl(void) const { return m_url_rest; }
  void setRestUrl(const std::string &url) { m_url_rest = url; }

  // is rest enabled
  bool isEnableREST(void) const { return m_bEnableREST; }
  void setEnableREST(bool bEnable) { m_bEnableREST = bEnable; }

  // is static web pages enabled
  bool isEnableStatic(void) const { return m_bEnableStatic; }
  void setEnableStatic(bool bEnable) { m_bEnableStatic = bEnable; }

  std::string getWebRoot(void) const { return m_web_root; }
  void setWebRoot(const std::string &web_root) { m_web_root = web_root; }

  std::string getCertPath(void) const { return m_cert_path; }
  void setCertPath(const std::string &cert_path) { m_cert_path = cert_path; }

  std::string getKeyPath(void) const { return m_key_path; }
  void setKeyPath(const std::string &key_path) { m_key_path = key_path; }

  /*!
      @brief Init and start the websocket server
      @param path Path to configuration file
      @param pguid Pointer to GUID
      @return true on success, false on failure
    */
  int open(std::string &path, const uint8_t *pguid);

  /*!
      @brief Close the websocket server
      @return true on success, false on failure
    */
  int close(void);

  /*!
   @brief Authentication of a websocket connection
   @param conn Pointer to the mongoose connection
    @param strContent Reference to string that holds the content to be
                       authenticated
   @param strIV Reference to string that will receive the IV
   @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int authentication(struct mg_connection *conn, std::string &strContent, std::string &strIV);

  /*!
    @brief Add an event to the send queue
    @param pEvent Pointer to the VSCP event
    @return VSCP_ERROR_SUCCESS on success, otherwise VSCP error code.
  */
  int addEvent2SendQueue(const vscpEvent *pEvent);

  /*!
    @brief Add an event to the receive queue
    @param pEvent Pointer to the VSCP event
    @return VSCP_ERROR_SUCCESS on success, otherwise VSCP error code.
  */
  int addEvent2ReceiveQueue(const vscpEvent *pEvent);

  /*!
    @brief Add an event ex to the receive queue
    @param ex Reference to the VSCP event ex
    @return VSCP_ERROR_SUCCESS on success, otherwise VSCP error code.
  */
  int addEvent2ReceiveQueue(vscpEventEx &ex);

  /*!
    @brief Send an event to a specific client
    @param pClientItem Pointer to the client item
    @param pEvent Pointer to the VSCP event
    @return VSCP_ERROR_SUCCESS on success, otherwise VSCP error code.
  */
  int sendEventToClient(CWebSockSession *pSessionItem, const vscpEvent *pEvent);

  /*!
    @brief Send an event to all connected and authorised clients
    @param pEvent Pointer to the VSCP event to send
    @return VSCP_ERROR_SUCCESS on success, otherwise VSCP error code.
  */
  int sendEventAllClients(const vscpEvent *pEvent);

  /*!
    @brief Send queued events to a specific client
    @param pSession Pointer to the websocket session
    @return VSCP_ERROR_SUCCESS on success, otherwise VSCP error code.
  */
  int sendQueueEventsToClient(CWebSockSession *pSession);

  /*!
    @brief Send a VSCP event over the websocket connection
    @param conn Pointer to the mongoose connection
    @param pev Pointer to the VSCP event
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  // int sendEvent(struct mg_connection *conn, vscpEvent *pev);

  /*!
    @brief Send a VSCP event ex over the websocket connection
    @param conn Pointer to the mongoose connection
    @param pev Pointer to the VSCP event
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  // int sendEvent(struct mg_connection *conn, vscpEventEx *pex);

  /*!
    @brief Post an incoming event to the websocket connection
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  void postIncomingEvent(void);

  /*!
   @brief Post incoming events to the websocket server
   @return true on success, false on failure
  */
  int websock_post_incomingEvents(void);

  /*!
    @brief Send an event to all connected and authorised clients
    @param pEvent Pointer to the VSCP event to send
  */
  // int sendEventAllClients(const vscpEvent *pEvent);

  /*!
    @brief Add a client to the client list
    @param pClientItem Pointer to client item
    @param id Unique id for the client
    @return true on success, false on failure
  */
  // bool addClient(CClientItem *pClientItem, uint32_t id);

  /*!
    @brief Add a client to the client list
    @param pClientItem Pointer to client item
    @param guid GUID for the client
    @return true on success, false on failure
  */
  // bool addClient(CClientItem *pClientItem, cguid &guid);

  /*!
    @brief Remove a client from the client list
    @param pClientItem Pointer to client item
  */
  // void removeClient(CClientItem *pClientItem);

  /*!
    @brief Create a new websocket session
    @param id Unique identifier for the websocket session
    @param pws_version Pointer to websocket version string
    @param ws_key Pointer to websocket key string
    @return Pointer to the new websocket session
  */
  CWebSockSession *newSession(unsigned long id, const char *pws_version, const uint8_t *pkey);

  /*!
    @brief Remove a websocket session
    @param id Unique identifier for the websocket session
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int removeSession(unsigned long id);

  /*!
    @brief Get a websocket session by its unique ID
    @param id Unique identifier for the websocket session
    @return Pointer to the websocket session or NULL if not found
  */
  CWebSockSession *getSession(unsigned long id);

  /*!
        Generate a random session key from a string key
        @param pKey Null terminated string key (max 255 characters)
        @param pSid Pointer to 33 byte sid that will receive sid
     */
  // bool generateSessionId(const char *pKey, char *pSid);

  /*!
    @brief Generate a random session ID (SID)
  */
  void generateSid(void);

  /*!
    Read encryption key
    @param path Path to file holding encryption key.
    @return True if read OK.
  */
  bool readEncryptionKey(const std::string &path);

  // Getters and setters for encryption key
  uint8_t *getEncryptionKey() { return m_encryptionKey; };
  void setEncryptionKey(const uint8_t *key) { memcpy(m_encryptionKey, key, 16); };

  //////////////////////////////////////////////////////////////////////////////
  //                                   WS1
  //////////////////////////////////////////////////////////////////////////////

  /*!
    @brief Handle when the websocket connection is ready
    @param conn Pointer to the mongoose connection
    @param cbdata Callback data
  */
  void ws1_readyHandler(struct mg_connection *conn, void *cbdata);

  /*!
    @brief Handle incoming data from the websocket connection
    @param conn Pointer to the mongoose connection
    @param wm Pointer to the websocket message
    @param cbdata Callback data
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int ws1_dataHandler(struct mg_connection *conn, struct mg_ws_message *wm);

  /*!
      @brief Handle incoming data from the websocket connection
      @param conn Pointer to the mongoose connection
      @param strWsPkt Websocket packet string
      @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
    */
  int ws1_message(struct mg_connection *conn, std::string &strWsPkt);

  /*!
    @brief Handle incoming command from the websocket connection
    @param conn Pointer to the mongoose connection
    @param strCmd Command string
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int ws1_command(struct mg_connection *conn, std::string &strCmd);

  //////////////////////////////////////////////////////////////////////////////
  //                                   WS2
  //////////////////////////////////////////////////////////////////////////////

  /*!
    @brief Handle when the websocket connection is ready
    @param conn Pointer to the mongoose connection
    @param cbdata Callback data
  */
  void ws2_readyHandler(struct mg_connection *conn, void *cbdata);

  /*!
    @brief Handle when the websocket connection is closed
    @param conn Pointer to the mongoose connection
    @param cbdata Callback data
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  // int ws2_connectHandler(const struct mg_connection *conn, void *cbdata);

  /*!
    @brief Handle when the websocket connection is closed
    @param conn Pointer to the mongoose connection
    @param cbdata Callback data
  */
  void ws2_closeHandler(const struct mg_connection *conn, void *cbdata);

  /*!
    @brief Handle incoming data from the websocket connection
    @param conn Pointer to the mongoose connection
    @param wm Pointer to the websocket message
    @param cbdata Callback data
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int ws2_dataHandler(struct mg_connection *conn, struct mg_ws_message *wm);

  /*!
      @brief Handle incoming data from the websocket connection
      @param conn Pointer to the mongoose connection
      @param strWsPkt Websocket packet string
      @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
    */
  int ws2_message(struct mg_connection *conn, std::string &strWsPkt);

  /*!
    @brief Handle incoming command from the websocket connection
    @param conn Pointer to the mongoose connection
    @param strCmd Command string
    @param jsonObj JSON object containing command arguments
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int ws2_command(struct mg_connection *conn, std::string &strCmd, json &jsonObj);

  /*!
    @brief Handle incoming xcommand from the websocket connection
    @param conn Pointer to the mongoose connection
    @param strCmd Command string
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int ws2_xcommand(struct mg_connection *conn, std::string &strCmd);

public:
  /// Parsed Config file
  json m_j_config;

  // ------------------------------------------------------------------------

  // * * * Configuration

  /// Path to configuration file
  std::string m_path;

  /// True if config is remote writable
  bool m_bWriteEnable;

  /// interface to listen on
  std::string m_interface;

  /// Path to user data base (must be present)
  std::string m_pathUsers;

  uint16_t m_maxClients; // Max clients (0 = no limit)

  bool m_bEnableWS1;    // True to enable ws1
  bool m_bEnableWS2;    // True to enable ws2
  bool m_bEnableREST;   // True to enable REST
  bool m_bEnableStatic; // True to enable static web pages

  /// Filters events we are not interested in
  vscpEventFilter m_rxfilter;

  /// TLS / SSL
  std::string m_tls_ca_path;          // Path to certificate authority file
  std::string m_tls_certificate_path; // Path to TLS certificate file
  std::string m_tls_private_key_path; // Path to TLS private key file

  /////////////////////////////////////////////////////////
  //                      Logging
  /////////////////////////////////////////////////////////

  bool m_bEnableFileLog;                    // True to enable logging
  spdlog::level::level_enum m_fileLogLevel; // log level
  std::string m_fileLogPattern;             // log file pattern
  std::string m_path_to_log_file;           // Path to logfile
  uint32_t m_max_log_size;                  // Max size for logfile before rotating occures
  uint16_t m_max_log_files;                 // Max log files to keep

  bool m_bConsoleLogEnable;                    // True to enable logging to console
  spdlog::level::level_enum m_consoleLogLevel; // Console log level
  std::string m_consoleLogPattern;             // Console log pattern

  // ------------------------------------------------------------------------

  bool m_bQuit; // Flag to indicate if the server should quit
  cguid m_guid; // Driver GUID

  sem_t m_semReceiveQueue;               // Semaphore for receive queue
  pthread_mutex_t m_mutexReceiveQueue;   // Mutex for receive queue
  std::list<vscpEvent *> m_receiveQueue; // Receive queue

  sem_t m_semSendQueue;               // Semaphore for send queue
  pthread_mutex_t m_mutexSendQueue;   // Mutex for send queue
  std::list<vscpEvent *> m_sendQueue; // Send queue

  pthread_t m_websockWorkerThread; // Worker thread for websocket server

  //**************************************************************************
  //                                USERS
  //**************************************************************************

  // The list of users
  CUserList m_userList;

  // Mutex for users
  pthread_mutex_t m_mutex_UserList;

  // ------------------------------------------------------------------------

private:
  bool m_bDebug; // Debug flag (gives extra debug output)

  uint16_t m_maxClientQueueSize; // Max size of client queues

  // URL for the websocket server  ws: or wss:
  std::string m_url;

  // Web root for the ws1 interface
  std::string m_url_ws1;

  // Web root for the ws2 interface
  std::string m_url_ws2;

  // Web root for the rest interface
  std::string m_url_rest;

  // Web root for the websocket server
  std::string m_web_root;

  // TSL certificate path for the websocket server
  std::string m_cert_path;

  // TSL key path for the websocket server
  std::string m_key_path;

  // Encryption key
  uint8_t m_encryptionKey[16];

  std::string m_listen_on; // Listen on this address

  // Websocket session mutex
  pthread_mutex_t m_mutex_websocketSession;

  // List of active websocket sessions
  std::map<unsigned long, CWebSockSession *> m_websocketSessionMap; // Key is connection id

  struct mg_mgr m_mgr; // Mongoose event manager
};

#endif // VSCP_WEBSOCKET_SRV_H__INCLUDED_