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

#include <string>
#include <vector>
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

#include <clientlist.h>
// #include <clientitem.h>
#include <userlist.h>
// #include <useritem.h>
#include <guid.h>

#include <mongoose.h>
#include <vscp.h>

#include <nlohmann/json.hpp> // Needs C++11  -std=c++11

#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"

// https://github.com/nlohmann/json
using json = nlohmann::json;

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

#define MAX_VSCPWS_MESSAGE_QUEUE (512)

// This is the time it takes for an expired websocket session to be
// removed by the system.
#define WEBSOCKET_EXPIRE_TIME (2 * 60)

// Authentication states
enum { WEBSOCK_CONN_STATE_NULL = 0, WEBSOCK_CONN_STATE_CONNECTED, WEBSOCK_CONN_STATE_DATA };

enum {
  WEBSOCK_ERROR_NO_ERROR                  = 0,  // Everything is OK.
  WEBSOCK_ERROR_SYNTAX_ERROR              = 1,  // Syntax error.
  WEBSOCK_ERROR_UNKNOWN_COMMAND           = 2,  // Unknown command.
  WEBSOCK_ERROR_TX_BUFFER_FULL            = 3,  // Transmit buffer full.
  WEBSOCK_ERROR_MEMORY_ALLOCATION         = 4,  // Problem allocating memory.
  WEBSOCK_ERROR_NOT_AUTHORIZED            = 5,  // Not authorized.
  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT = 6,  // Not authorized to send events.
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
#define WEBSOCK_STR_ERROR_NOT_AUTHORIZED            "Not authorized."
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
    @brief Initialize the websocket session
    @param pClientItem Pointer to client item
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int init(CClientItem *pClientItem);

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

  // /*!
  //   @brief Handle incoming data from the websocket connection
  //   @param conn Pointer to the mongoose connection
  //   @param bits Bits indicating the type of data
  //   @param data Pointer to the data
  //   @param len Length of the data
  //   @param cbdata Callback data
  //   @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  // */
  // int ws1_dataHandler(struct mg_connection *conn, int bits, char *data, size_t len, void *cbdata);

  // /*!
  //   @brief Handle incoming data from the websocket connection
  //   @param conn Pointer to the mongoose connection
  //   @param bits Bits indicating the type of data
  //   @param data Pointer to the data
  //   @param len Length of the data
  //   @param cbdata Callback data
  //   @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  // */
  // int ws1_message(struct mg_connection *conn, std::string &strWsPkt);

  // /*!
  //   @brief Handle incoming data from the websocket connection
  //   @param conn Pointer to the mongoose connection
  //   @param strCmd Command string
  //   @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  // */
  // int ws1_command(struct mg_connection *conn, std::string &strCmd);

  // /*!
  //   @brief Handle incoming data from the websocket connection
  //   @param conn Pointer to the mongoose connection
  //   @param bits Bits indicating the type of data
  //   @param data Pointer to the data
  //   @param len Length of the data
  //   @param cbdata Callback data
  //   @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  // */
  // int ws2_dataHandler(struct mg_connection *conn, int bits, char *data, size_t len, void *cbdata);

  // /*!
  //     @brief Handle incoming data from the websocket connection
  //     @param conn Pointer to the mongoose connection
  //     @param strWsPkt Websocket packet string
  //     @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  //   */
  // int ws2_message(struct mg_connection *conn, std::string &strWsPkt);

  // /*!
  //   @brief Handle incoming command from the websocket connection
  //   @param conn Pointer to the mongoose connection
  //   @param strCmd Command string
  //   @param jsonObj JSON object containing command arguments
  //   @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  // */
  // int ws2_command(struct mg_connection *conn, std::string &strCmd, json &jsonObj);

  // /*!
  //   @brief Handle incoming xcommand from the websocket connection
  //   @param conn Pointer to the mongoose connection
  //   @param strCmd Command string
  //   @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  // */
  // int ws2_xcommand(struct mg_connection *conn, std::string &strCmd);

  // Fetch client item object
  CClientItem *getClientItem(void) { return m_pClientItem; }

  /*!
    @brief Get the unique ID for this session
    @return Pointer to the unique ID for this session
  */
  const char *getWebsocketKey(void) { return m_key; }

  /*!
    @brief Get the session ID (SID) for this session
    @return Pointer to the session ID for this session
  */
  const char *getSid(void) { return m_sid; }

  uint8_t getWsType(void) { return m_wstypes; }
  void setWsType(uint8_t wstype) { m_wstypes = wstype; }

  int getConnState(void) { return m_conn_state; }
  void setConnState(int state) { m_conn_state = state; }

  // Get the client connection
  struct mg_connection *getConn(void) { return m_conn; }
  void setConn(struct mg_connection *conn) { m_conn = conn; }

  // Get last active time
  time_t getLastActiveTime(void) { return lastActiveTime; }
  void setLastActiveTime(time_t t) { lastActiveTime = t; }

private:
  // ws type (0 = not set, 1 = ws1, 2 = ws2)
  uint8_t m_wstypes;

  // Connection state (see enums above)
  int m_conn_state;

  // Client connection
  struct mg_connection *m_conn;

  // Unique ID for this session.
  char m_key[33]; // Sec-WebSocket-Key

  // 16 byte iv (SID) for this session
  char m_sid[33];

  // Protocol version
  int m_version; // Sec-WebSocket-Version

  // Time when this session was last active.
  time_t lastActiveTime;

  // Concatenated message receive
  std::string m_strConcatenated;

  // Client structure for websocket
  CClientItem *m_pClientItem;
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
void
websock_post_incomingEvents(void);

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
  int init(std::string &url,
           std::string &web_root,
           std::string &ca_path,
           std::string &cert_path,
           std::string &key_path);

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

  // Getters/setters for URL, web root, CA path, cert path and key path
  std::string getUrl(void) const { return m_url; }
  void setUrl(const std::string &url) { m_url = url; }

  std::string getWebRoot(void) const { return m_web_root; }
  void setWebRoot(const std::string &web_root) { m_web_root = web_root; }

  std::string getCaPath(void) const { return m_ca_path; }
  void setCaPath(const std::string &ca_path) { m_ca_path = ca_path; }

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
   @param strIV Reference to string that will receive the IV
   @param strCrypto Reference to string that will receive the crypto key
   @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int authentication(struct mg_connection *conn, std::string &strIV, std::string &strCrypto);

  /*!
    @brief Send a VSCP event over the websocket connection
    @param conn Pointer to the mongoose connection
    @param pev Pointer to the VSCP event
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int sendEvent(struct mg_connection *conn, vscpEvent *pev);

  /*!
    @brief Send a VSCP event ex over the websocket connection
    @param conn Pointer to the mongoose connection
    @param pev Pointer to the VSCP event
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int sendEvent(struct mg_connection *conn, vscpEventEx *pex);

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
    @brief Send an event to all connected and authorized clients
    @param pEvent Pointer to the VSCP event to send
  */
  void sendEventAllClients(const vscpEvent *pEvent);

  /*!
        Generate a random session key from a string key
        @param pKey Null terminated string key (max 255 characters)
        @param pSid Pointer to 33 byte sid that will receive sid
     */
  bool generateSessionId(const char *pKey, char *pSid);

  /*!
    Read encryption key
    @param path Path to file holding encryption key.
    @return True if read OK.
  */
  bool readEncryptionKey(const std::string &path);

  //////////////////////////////////////////////////////////////////////////////
  //                                   WS1
  //////////////////////////////////////////////////////////////////////////////

  /*!
    @brief Handle incoming data from the websocket connection
    @param conn Pointer to the mongoose connection
    @param bits Bits indicating the type of data
    @param data Pointer to the data
    @param len Length of the data
    @param cbdata Callback data
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int ws1_dataHandler(struct mg_connection *conn, int bits, char *data, size_t len, void *cbdata);

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
    @brief Handle incoming data from the websocket connection
    @param conn Pointer to the mongoose connection
    @param bits Bits indicating the type of data
    @param data Pointer to the data
    @param len Length of the data
    @param cbdata Callback data
    @return VSCP_ERROR_SUCCESS if all is OK, otherwise VSCP error code.
  */
  int ws2_dataHandler(struct mg_connection *conn, int bits, char *data, size_t len, void *cbdata);

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
  std::string m_pathConfig;

  /// True if config is remote writable
  bool m_bWriteEnable;

  /// interface to listen on
  std::string m_interface;

  /// Path to user data base (must be present)
  std::string m_pathUsers;

  /*
    If true our own sent events will be received, if
    false they will be masked. The clientid for
    the channel is used to detect from whom the events
    originates. obid will be set to this clientid if
    it is set to zero on send. The command "CHID" command
    can be used to get the clientid for the channel.
  */
  bool m_bReceiveOwnEvents;

  /// Response timeout
  uint32_t m_responseTimeout;

  /// Filters for input/output
  vscpEventFilter m_filterIn;
  vscpEventFilter m_filterOut;

  /// TLS / SSL
  std::string m_tls_certificate;
  std::string m_tls_certificate_chain;
  bool m_tls_verify_peer;
  std::string m_tls_ca_path;
  std::string m_tls_ca_file;
  uint8_t m_tls_verify_depth;
  bool m_tls_default_verify_paths;
  std::string m_tls_cipher_list;
  uint8_t m_tls_protocol_version;
  bool m_tls_short_trust;

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

  bool m_bQuit;                          // Flag to indicate if the server should quit
  uint8_t m_guid[16];                    // Driver GUID
  sem_t m_semReceiveQueue;               // Semaphore for receive queue
  pthread_mutex_t m_mutexReceiveQueue;   // Mutex for receive queue
  std::list<vscpEvent *> m_receiveQueue; // Receive queue

  //**************************************************************************
  //                                USERS
  //**************************************************************************

  // The list of users
  CUserList m_userList;

  // Mutex for users
  pthread_mutex_t m_mutex_UserList;

  //**************************************************************************
  //                                CLIENTS
  //**************************************************************************

  // The list with active clients. (protecting mutex in object)
  CClientList m_clientList;

  // Mutex for client queue
  pthread_mutex_t m_mutex_clientList;

  // Queue
  std::list<vscpEvent *> m_sendList;
  std::list<vscpEvent *> m_receiveList;

  // ------------------------------------------------------------------------

private:
  // URL for the websocket server  ws: or wss:
  std::string m_url;

  // Web root for the websocket server
  std::string m_web_root;

  // TSL CA path for the websocket server
  std::string m_ca_path;

  // TSL certificate path for the websocket server
  std::string m_cert_path;

  // TSL key path for the websocket server
  std::string m_key_path;

  std::string m_listen_on; // Listen on this address

  // Websocket session mutex
  pthread_mutex_t m_mutex_websocketSession;

  // List of active websocket sessions
  std::list<CWebSockSession *> m_websocketSessions;

  struct mg_mgr m_mgr; // Mongoose event manager
};

#endif // VSCP_WEBSOCKET_SRV_H__INCLUDED_