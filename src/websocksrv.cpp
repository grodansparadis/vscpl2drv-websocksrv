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

#include <version.h>
#include <vscp.h>
#include <vscp-aes.h>
#include <vscp-debug.h>
#include <vscphelper.h>

#include "websocksrv.h"

#include <mustache.hpp>
#include <nlohmann/json.hpp> // Needs C++11  -std=c++11

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#define XML_BUFF_SIZE 0xffff

// https://github.com/nlohmann/json
using json = nlohmann::json;

using namespace kainjow::mustache;

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
// CWebSockSrv::ws1_command(struct mg_connection *conn, struct websock_session *pSession, std::string &strCmd);

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

CWebSockSession::CWebSockSession(void)
{
  m_wstypes    = WS_TYPE_1; // ws1 is default
  m_conn_state = WEBSOCK_CONN_STATE_NULL;
  memset(m_key, 0, 33);
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

  // memset(m_sid, 0, sizeof(pSession->m_sid));
  // memcpy(m_sid, hexiv, 32);
  // memset(m_key, 0, sizeof(m_key));

  // Init.
  // strcpy(m_key, ws_key); // Save key

  // Attach and initiate client object
  m_pClientItem = new CClientItem(); // Create client
  if (NULL == m_pClientItem) {
    syslog(LOG_ERR, "[Websockets] New session: Unable to create client object.");
    // delete pSession;
    // return NULL;
  }

  m_pClientItem->bAuthenticated = false;          // Not authenticated in yet
  vscp_clearVSCPFilter(&m_pClientItem->m_filter); // Clear filter

  // This is an active client
  m_pClientItem->m_bOpen         = false;
  m_pClientItem->m_dtutc         = vscpdatetime::Now();
  m_pClientItem->m_type          = CLIENT_ITEM_INTERFACE_TYPE_CLIENT_WEBSOCKET;
  m_pClientItem->m_strDeviceName = ("Websocket client level II  driver.");
};

CWebSockSession::~CWebSockSession(void)
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

CWebSockSrv::CWebSockSrv(void)
{
  // Initialize mutex
  pthread_mutex_init(&m_mutex_websocketSession, NULL);

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

CWebSockSrv::~CWebSockSrv(void)
{
  ;
}

////////////////////////////////////////////////////////////////////////////////
// init
//

int
CWebSockSrv::init(std::string &url,
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
  pthread_mutex_init(&m_mutex_websocketSession, NULL);

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// doLoadConfig
//

int
CWebSockSrv::doLoadConfig(std::string &path)
{
  try {
    std::ifstream in(path, std::ifstream::in);
    in >> m_j_config;
  }
  catch (json::parse_error) {
    spdlog::critical("Failed to load/parse JSON configuration.");
    return VSCP_ERROR_PARSING;
  }

  // write
  if (m_j_config.contains("write")) {
    try {
      m_bWriteEnable = m_j_config["write"].get<bool>();
    }
    catch (const std::exception &ex) {
      spdlog::error("Failed to read 'write' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("Failed to read 'write' due to unknown error.");
    }
  }
  else {
    spdlog::error("ReadConfig: Failed to read LOGGING 'write' Defaults will be used.");
  }

  // VSCP key file
  if (m_j_config.contains("key-file") && m_j_config["key-file"].is_string()) {
    if (!readEncryptionKey(m_j_config["key-file"].get<std::string>())) {
      spdlog::warn("WARNING!!! Default key will be used.");
    }
  }
  else {
    spdlog::warn("WARNING!!! Default key will be used.");
  }

  // Receive own events
  if (m_j_config.contains("receive-sent-events") && m_j_config["receive-sent-events"].is_boolean()) {
    m_bReceiveOwnEvents = m_j_config["receive-sent-events"].get<bool>();
    if (m_bReceiveOwnEvents) {
      spdlog::info("Our sent event will be received.");
    }
    else {
      spdlog::info("Our sent events will be masked.");
    }
  }
  else {
    spdlog::info("Our sent event will be received.");
  }

  // Logging
  if (m_j_config.contains("logging") && m_j_config["logging"].is_object()) {

    json j = m_j_config["logging"];

    // Logging: file-log-level
    if (j.contains("file-log-level")) {
      std::string str;
      try {
        str = j["file-log-level"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("[vscpl2drv-tcpipsrv]Failed to read 'file-log-level' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("[vscpl2drv-tcpipsrv]Failed to read 'file-log-level' due "
                      "to unknown error.");
      }
      vscp_makeLower(str);
      if (std::string::npos != str.find("off")) {
        m_fileLogLevel = spdlog::level::off;
      }
      else if (std::string::npos != str.find("critical")) {
        m_fileLogLevel = spdlog::level::critical;
      }
      else if (std::string::npos != str.find("err")) {
        m_fileLogLevel = spdlog::level::err;
      }
      else if (std::string::npos != str.find("warn")) {
        m_fileLogLevel = spdlog::level::warn;
      }
      else if (std::string::npos != str.find("info")) {
        m_fileLogLevel = spdlog::level::info;
      }
      else if (std::string::npos != str.find("debug")) {
        m_fileLogLevel = spdlog::level::debug;
      }
      else if (std::string::npos != str.find("trace")) {
        m_fileLogLevel = spdlog::level::trace;
      }
      else {
        spdlog::error("ReadConfig: LOGGING 'file-log-level' has invalid value "
                      "[{}]. Default value used.",
                      str);
      }
    }
    else {
      spdlog::error("ReadConfig: Failed to read LOGGING 'file-log-level' "
                    "Defaults will be used.");
    }

    // Logging: file-pattern
    if (j.contains("file-pattern")) {
      try {
        m_fileLogPattern = j["file-pattern"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig:Failed to read 'file-pattern' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'file-pattern' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read LOGGING 'file-pattern' "
                    "Defaults will be used.");
    }

    // Logging: file-path
    if (j.contains("file-path")) {
      try {
        m_path_to_log_file = j["file-path"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("Failed to read 'file-path' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'file-path' due to unknown error.");
      }
    }
    else {
      spdlog::error("ReadConfig: Failed to read LOGGING 'file-path' Defaults "
                    "will be used.");
    }

    // Logging: file-max-size
    if (j.contains("file-max-size")) {
      try {
        m_max_log_size = j["file-max-size"].get<uint32_t>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig:Failed to read 'file-max-size' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'file-max-size' due to unknown error.");
      }
    }
    else {
      spdlog::error("ReadConfig: Failed to read LOGGING 'file-max-size' "
                    "Defaults will be used.");
    }

    // Logging: file-max-files
    if (j.contains("file-max-files")) {
      try {
        m_max_log_files = j["file-max-files"].get<uint16_t>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig:Failed to read 'file-max-files' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'file-max-files' due to unknown error.");
      }
    }
    else {
      spdlog::error("ReadConfig: Failed to read LOGGING 'file-max-files' "
                    "Defaults will be used.");
    }

  } // Logging
  else {
    spdlog::error("ReadConfig: No logging has been setup.");
  }

  ///////////////////////////////////////////////////////////////////////////
  //                          Setup logger
  ///////////////////////////////////////////////////////////////////////////

  // Console log
  auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  if (m_bConsoleLogEnable) {
    console_sink->set_level(m_consoleLogLevel);
    console_sink->set_pattern(m_consoleLogPattern);
  }
  else {
    // If disabled set to off
    console_sink->set_level(spdlog::level::off);
  }

  // auto rotating =
  // std::make_shared<spdlog::sinks::rotating_file_sink_mt>("log_filename",
  // 1024*1024, 5, false);
  auto rotating_file_sink =
    std::make_shared<spdlog::sinks::rotating_file_sink_mt>(m_path_to_log_file.c_str(), m_max_log_size, m_max_log_files);

  if (m_bEnableFileLog) {
    rotating_file_sink->set_level(m_fileLogLevel);
    rotating_file_sink->set_pattern(m_fileLogPattern);
  }
  else {
    // If disabled set to off
    rotating_file_sink->set_level(spdlog::level::off);
  }

  std::vector<spdlog::sink_ptr> sinks{ console_sink, rotating_file_sink };
  auto logger = std::make_shared<spdlog::async_logger>("logger",
                                                       sinks.begin(),
                                                       sinks.end(),
                                                       spdlog::thread_pool(),
                                                       spdlog::async_overflow_policy::block);
  // The separate sub loggers will handle trace levels
  logger->set_level(spdlog::level::trace);
  spdlog::register_logger(logger);

  // ------------------------------------------------------------------------

  // interface
  if (m_j_config.contains("interface")) {
    try {
      m_interface = m_j_config["interface"].get<std::string>();
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'interface' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'interface' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'interface' Defaults will be used.");
  }

  // Path to user database
  if (m_j_config.contains("path-users")) {
    try {
      m_pathUsers = m_j_config["path-users"].get<std::string>();
      if (!m_userList.loadUsersFromFile(m_pathUsers)) {
        spdlog::critical("ReadConfig: Failed to load users from file "
                         "'user-path'='{}'. Terminating!",
                         path);
        return false;
      }
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'path-users' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'path-users' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'path-users' Defaults will be used.");
  }

  // Response timeout m_responseTimeout
  if (m_j_config.contains("response-timeout")) {
    try {
      m_responseTimeout = m_j_config["response-timeout"].get<uint32_t>();
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'response-timeout' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'response-timeout' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'response-timeout' Defaults will be used.");
  }

  // Filter
  if (m_j_config.contains("filter") && m_j_config["filter"].is_object()) {

    json j = m_j_config["filter"];

    // IN filter
    if (j.contains("in-filter")) {
      try {
        std::string str = j["in-filter"].get<std::string>();
        vscp_readFilterFromString(&m_filterIn, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig: Failed to read 'in-filter' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig: Failed to read 'in-filter' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'in-filter' Defaults "
                    "will be used.");
    }

    // IN mask
    if (j.contains("in-mask")) {
      try {
        std::string str = j["in-mask"].get<std::string>();
        vscp_readMaskFromString(&m_filterIn, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig: Failed to read 'in-mask' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig: Failed to read 'in-mask' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'in-mask' Defaults will be used.");
    }

    // OUT filter
    if (j.contains("out-filter")) {
      try {
        std::string str = j["in-filter"].get<std::string>();
        vscp_readFilterFromString(&m_filterOut, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig: Failed to read 'out-filter' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig: Failed to read 'out-filter' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'out-filter' Defaults will be used.");
    }

    // OUT mask
    if (j.contains("out-mask")) {
      try {
        std::string str = j["out-mask"].get<std::string>();
        vscp_readMaskFromString(&m_filterOut, str.c_str());
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig: Failed to read 'out-mask' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig: Failed to read 'out-mask' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'out-mask' Defaults will be used.");
    }
  }

  // TLS / SSL
  if (m_j_config.contains("tls") && m_j_config["tls"].is_object()) {

    json j = m_j_config["tls"];

    // Certificate
    if (j.contains("certificate")) {
      try {
        m_tls_certificate = j["certificate"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig: Failed to read 'certificate' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig: Failed to read 'certificate' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'certificate' Defaults will be used.");
    }

    // certificate chain
    if (j.contains("certificate_chain")) {
      try {
        m_tls_certificate_chain = j["certificate_chain"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig: Failed to read 'certificate_chain' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig: Failed to read 'certificate_chain' due to "
                      "unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'certificate_chain' Defaults "
                    "will be used.");
    }

    // verify peer
    if (j.contains("verify-peer")) {
      try {
        m_tls_verify_peer = j["verify-peer"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig: Failed to read 'verify-peer' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig: Failed to read 'verify-peer' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'verify-peer' Defaults will be used.");
    }

    // CA Path
    if (j.contains("ca-path")) {
      try {
        m_tls_ca_file = j["ca-path"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig: Failed to read 'ca-path' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig: Failed to read 'ca-path' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: ReadConfig: Failed to read 'ca-path' Defaults "
                    "will be used.");
    }

    // CA File
    if (j.contains("ca-file")) {
      try {
        m_tls_ca_file = j["ca-file"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig: Failed to read 'ca-file' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig: Failed to read 'ca-file' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: ReadConfig: Failed to read 'ca-file' Defaults "
                    "will be used.");
    }

    // Verify depth
    if (j.contains("verify_depth")) {
      try {
        m_tls_verify_depth = j["verify_depth"].get<uint16_t>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig: Failed to read 'verify_depth' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig: Failed to read 'verify_depth' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'verify_depth' Defaults will be used.");
    }

    // Default verify paths
    if (j.contains("default-verify-paths")) {
      try {
        m_tls_default_verify_paths = j["default-verify-paths"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig:Failed to read 'default-verify-paths' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'default-verify-paths' due to "
                      "unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'default-verify-paths' "
                    "Defaults will be used.");
    }

    // Chiper list
    if (j.contains("cipher-list")) {
      try {
        m_tls_cipher_list = j["cipher-list"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig:Failed to read 'cipher-list' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'cipher-list' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'cipher-list' Defaults will be used.");
    }

    // Protocol version
    if (j.contains("protocol-version")) {
      try {
        m_tls_protocol_version = j["protocol-version"].get<uint16_t>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig:Failed to read 'protocol-version' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'protocol-version' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'protocol-version' Defaults will be used.");
    }

    // Short trust
    if (j.contains("short-trust")) {
      try {
        m_tls_short_trust = j["short-trust"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig:Failed to read 'short-trust' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'short-trust' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'short-trust' Defaults will be used.");
    }
  }

  // vscpEvent ev;
  // ev.vscp_class = VSCP_CLASS2_HLO;
  // ev.vscp_type = VSCP2_TYPE_HLO_COMMAND;

  // std::string jj = "{\"op\" : 1, \"name\": \"\"}";
  // json j;
  // j["op"] = "noop";
  // j["arg"]["currency"] = "USD";
  // j["arg"]["value"] = 42.99;
  // j["arr"] = json::array();
  // j["arr"][0]["ettan"] = 1;
  // j["arr"][0]["tvan"] = 2;
  // j["arr"][1]["ettan"] = 1;
  // j["arr"][1]["tvan"] = 2;
  // j["arr"][2]["ettan"] = 1;
  // j["arr"][2]["tvan"] = 2;
  // printf("%s\n",j.dump().c_str());

  // json aa;
  // aa["ettan"] = 55;
  // aa["tva"] = 66;
  // j["arr"][1] = aa;
  // j["arr"][3] = aa;
  // printf("%s\n",j.dump().c_str());
  // j["arr"].erase(1);

  // printf("%s\n",j.dump().c_str());

  // ev.pdata = new uint8_t[200];

  // memset(ev.pdata, 0, sizeof(ev.pdata));
  // for ( int i=0; i<16; i++) {
  //     ev.pdata[i] = 11 * i;
  // }
  // ev.pdata[16] = 0x20;  // JSON, no encryption
  // memcpy(ev.pdata+17, j.dump().c_str(), j.dump().length());
  // ev.sizeData = 16 + 1 + (uint16_t)j.dump().length();

  // handleHLO(&ev);

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// doSaveConfig
//

int
CWebSockSrv::doSaveConfig(void)
{
  if (m_j_config.value("write", false)) {}
  return VSCP_ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// start
//

int
CWebSockSrv::start(void)
{
  // TODO_ Start workerthread

  // mg_mgr_init(&m_mgr); // Initialise mongoose event manager
  // printf("Starting WS listener on %s/websocket\n", m_listen_on.c_str());
  // mg_http_listen(&m_mgr, m_listen_on.c_str(), fn, NULL); // Create HTTP listener
  // for (;;) {
  //   mg_mgr_poll(&mgr, 1000); // Infinite event loop
  // }
  // mg_mgr_free(&m_mgr);      // Free mongoose event manager

  return VSCP_ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// stop
//

int
CWebSockSrv::stop(void)
{
  // TODO: Stop workerthread
  // mg_mgr_free(&m_mgr);
  return VSCP_ERROR_SUCCESS;
}
////////////////////////////////////////////////////////////////////////////////
// open
//

int
CWebSockSrv::open(std::string &path, const uint8_t *pguid)
{
  int rv;

  // Save path to config file
  m_pathConfig = path;

  // Read configuration file
  if (VSCP_ERROR_SUCCESS != (rv = doLoadConfig(path))) {
    syslog(LOG_ERR, "[Websocket Server] Failed to load configuration file.");
    return rv;
  }

  // Set the driver GUID
  if (NULL != pguid) {
    memcpy(m_guid, pguid, 16);
  }
  else {
    // No GUID specified - use all zeros
    memset(m_guid, 0, 16);
  }

  // // Initialize user list
  // if (!m_userList.init()) {
  //   syslog(LOG_ERR, "[Websocket Server] Failed to initialize user list.");
  //   return VSCP_ERROR_FAILURE;
  // }

  // // Read user list
  // if (!m_userList.loadFromDatabase()) {
  //   syslog(LOG_ERR, "[Websocket Server] Failed to load user list from database.");
  //   return VSCP_ERROR_FAILURE;
  // }

  // Start the server
  if (VSCP_ERROR_SUCCESS != start()) {
    syslog(LOG_ERR, "[Websocket Server] Failed to start server.");
    return VSCP_ERROR_ERROR;
  }

  // Everything is OK
  m_bQuit = false;

  // Open the websocket server
  return VSCP_ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// close
//

int
CWebSockSrv::close(void)
{
  // Stop the server
  if (VSCP_ERROR_SUCCESS != stop()) {
    syslog(LOG_ERR, "[Websocket Server] Failed to stop server.");
    return VSCP_ERROR_ERROR;
  }

  // Everything is OK
  m_bQuit = true;

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
CWebSockSrv::authentication(struct mg_connection *conn, std::string &strIV, std::string &strCrypto)
{
  uint8_t buf[2048], secret[2048];
  uint8_t iv[16];
  std::string strUser, strPassword;

  bool bValidHost = false;

  // Check pointers
  if ((NULL == conn)) {
    syslog(LOG_ERR, "[Websocket Client] Authentication: Invalid connection context pointer.");
    return false;
  }

  CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;

  if (NULL == pSession) {
    syslog(LOG_ERR, "[Websocket Client] Authentication: Invalid session pointer. ");
    return false;
  }

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
  AES_CBC_decrypt_buffer(AES128, buf, secret, len, (const uint8_t *) pSession->getWebsocketKey(), iv);

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
  // TODO bValidHost = pUserItem->isAllowedToConnect(inet_addr(conn->rem.mg_addr.sin_addr.s_addr));

  if (!bValidHost) {
    // Log valid login
    // syslog(LOG_ERR,
    //        "[Websocket Client] Authentication: Host "
    //        "[%s] NOT allowed to connect.",
    //        conn->rem.ip.c_str());
    return false;
  }

  // TODO
  // if (!vscp_isPasswordValid(pUserItem->getPasswordHash(), strPassword)) {
  //   syslog(LOG_ERR,
  //          "[Websocket Client] Authentication: User %s at host "
  //          "[%s] gave wrong password.",
  //          (const char *) strUser.c_str(),
  //          conn->rem);
  //   return false;
  // }

  // pSession->getClientItem()->bAuthenticated = true;

  // // Add user to client
  // pSession->getClientItem()->m_pUserItem = pUserItem;

  // // Copy in the user filter
  // memcpy(&pSession->getClientItem()->m_filter, pUserItem->getUserFilter(), sizeof(vscpEventFilter));

  // Log valid login
  // syslog(LOG_ERR,
  //        "[Websocket Client] Authentication: Host [%s] "
  //        "User [%s] allowed to connect.",
  //        conn->rem.ip.c_str(),
  //        (const char *) strUser.c_str());

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// newSession
//

// websock_session *
// CWebSockSrv::newSession(const struct mg_connection *conn)
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
//   memset(pSession->m_key, 0, sizeof(pSession->m_key));

//   // Init.
//   strcpy(pSession->m_key, ws_key); // Save key
//   pSession->getConn()       = (struct mg_connection *) conn;
//   pSession->getConnState() = WEBSOCK_CONN_STATE_CONNECTED;
//   pSession->m_version    = atoi(ws_version); // Store protocol version

//   pSession->getClientItem() = new CClientItem(); // Create client
//   if (NULL == pSession->getClientItem()) {
//     syslog(LOG_ERR, "[Websockets] New session: Unable to create client object.");
//     delete pSession;
//     return NULL;
//   }

//   pSession->getClientItem()->bAuthenticated = false;          // Not authenticated in yet
//   vscp_clearVSCPFilter(&pSession->getClientItem()->m_filter); // Clear filter

//   // This is an active client
//   pSession->getClientItem()->m_bOpen         = false;
//   pSession->getClientItem()->m_dtutc         = vscpdatetime::Now();
//   pSession->getClientItem()->m_type          = CLIENT_ITEM_INTERFACE_TYPE_CLIENT_WEBSOCKET;
//   pSession->getClientItem()->m_strDeviceName = ("Internal websocket client.");

//   // Add the client to the Client List
//   pthread_mutex_lock(&m_clientList.m_mutexItemList);
//   if (!addClient(pSession->getClientItem())) {
//     // Failed to add client
//     delete pSession->getClientItem();
//     pSession->getClientItem() = NULL;
//     pthread_mutex_unlock(&m_clientList.m_mutexItemList);
//     syslog(LOG_ERR, ("Websocket server: Failed to add client. Terminating thread."));
//     return NULL;
//   }
//   pthread_mutex_unlock(&m_clientList.m_mutexItemList);

//   pthread_mutex_lock(&m_mutex_websocketSession);
//   m_websocketSessions.push_back(pSession);
//   pthread_mutex_unlock(&m_mutex_websocketSession);

//   // Use the session object as user data
//   mg_set_user_connection_data(pSession->getConn(), (void *) pSession);

//   return pSession;
// }

///////////////////////////////////////////////////////////////////////////////
// sendEvent
//
// Send event to all other clients.
//

// int
// CWebSockSrv::sendEvent(struct mg_connection *conn, vscpEvent *pev)
// {
//   // Check pointers
//   if (NULL == conn) {
//     syslog(LOG_ERR, "Internal error: sendEvent - conn == NULL");
//     return false;
//   }

//   CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;
//   if (NULL == pSession) {
//     syslog(LOG_ERR, "Internal error: sendEvent - pSession == NULL");
//     return false;
//   }

//   if (NULL == pev) {
//     syslog(LOG_ERR, "Internal error: sendEvent - pEvent == NULL");
//     return false;
//   }

//   return sendEvent(pSession->getClientItem(), pev);
// }

///////////////////////////////////////////////////////////////////////////////
// sendEventEx
//
// Send event to all other clients.
//

// bool
// CWebSockSrv::sendEventEx(struct mg_connection *conn, vscpEventEx *pex)
// {
//   // Check pointers
//   if (NULL == conn) {
//     syslog(LOG_ERR, "Internal error: sendEvent - conn == NULL");
//     return false;
//   }

//   CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;
//   if (NULL == pSession) {
//     syslog(LOG_ERR, "Internal error: sendEvent - pSession == NULL");
//     return false;
//   }

//   if (NULL == pex) {
//     syslog(LOG_ERR, "Internal error: sendEvent - pEvent == NULL");
//     return false;
//   }

//   return sendEvent(pSession->getClientItem(), pex);
// }

///////////////////////////////////////////////////////////////////////////////
// postIncomingEvent
//

void
CWebSockSrv::postIncomingEvent(void)
{
  pthread_mutex_lock(&m_mutex_websocketSession);

  std::list<CWebSockSession *>::iterator iter;
  for (iter = m_websocketSessions.begin(); iter != m_websocketSessions.end(); ++iter) {

    CWebSockSession *pSession = *iter;
    if (NULL == pSession) {
      continue;
    }

    // Should be a client item... hmm.... client disconnected
    if (NULL == pSession->getClientItem()) {
      continue;
    }

    if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
      continue;
    }

    if (NULL == pSession->getConn()) {
      continue;
    }

    if (pSession->getClientItem()->m_bOpen && pSession->getClientItem()->m_clientInputQueue.size()) {

      vscpEvent *pEvent;
      pthread_mutex_lock(&pSession->getClientItem()->m_mutexClientInputQueue);
      pEvent = pSession->getClientItem()->m_clientInputQueue.front();
      pSession->getClientItem()->m_clientInputQueue.pop_front();
      pthread_mutex_unlock(&pSession->getClientItem()->m_mutexClientInputQueue);
      if (NULL != pEvent) {

        // Run event through filter
        if (vscp_doLevel2Filter(pEvent, &pSession->getClientItem()->m_filter)) {

          // User must be authorized to receive events
          if (!(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
            continue;
          }

          std::string str;
          if (vscp_convertEventToString(str, pEvent)) {

#ifdef __VSCP_DEBUG_WEBSOCKET_RX
            syslog(LOG_DEBUG, "Received ws event %s", str.c_str());
#endif

            // Write it out
            if (WS_TYPE_1 == pSession->getWsType()) {
              str = ("E;") + str;
              mg_ws_send(pSession->getConn(), (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
            }
            else if (WS_TYPE_2 == pSession->getWsType()) {
              std::string strEvent;
              vscp_convertEventToJSON(strEvent, pEvent);
              std::string str = vscp_str_format(WS2_EVENT, strEvent.c_str());
              mg_ws_send(pSession->getConn(), (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
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
// CWebSockSrv::ws1_connectHandler(const struct mg_connection *conn, void *cbdata)
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

#ifdef __VSCP_DEBUG_WEBSOCKET
//     syslog(LOG_ERR, "[Websocket ws1] WS1 Connection: client %s", (reject ? "rejected" : "accepted"));
#endif

//   return reject;
// }

////////////////////////////////////////////////////////////////////////////////
// ws1_closeHandler
//

// void
// CWebSockSrv::ws1_closeHandler(const struct mg_connection *conn, void *cbdata)
// {
//   struct mg_context *ctx    = mg_get_context(conn);
//   CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;

//   // Check pointers
//   if (NULL == conn) {
//     return;
//   }

//   if (NULL == pSession) {
//     return;
//   }

//   if (pSession->getConn() != conn) {
//     return;
//   }

//   if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
//     return;
//   }

//   mg_lock_context(ctx);

//   // Record activity
//   pSession->lastActiveTime = time(NULL);

//   pSession->getConnState() = WEBSOCK_CONN_STATE_NULL;
//   pSession->getConn()       = NULL;
//   m_clientList.removeClient(pSession->getClientItem());
//   pSession->getClientItem() = NULL;

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
// CWebSockSrv::ws1_readyHandler(struct mg_connection *conn, void *cbdata)
// {
//   // Check pointers
//   if (NULL == conn) {
//     return;
//   }

//   CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;
//   if (NULL == pSession) {
//     return;
//   }

//   if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
//     return;
//   }

//   // Record activity
//   pSession->lastActiveTime = time(NULL);

//   // Start authentication
//   std::string str = vscp_str_format(("+;AUTH0;%s"), pSession->m_sid);
//   mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

//   pSession->getConnState() = WEBSOCK_CONN_STATE_DATA;
// }

////////////////////////////////////////////////////////////////////////////////
// ws1_dataHandler
//

int
CWebSockSrv::ws1_dataHandler(struct mg_connection *conn, int bits, char *data, size_t len, void *cbdata)
{
  std::string strWsPkt;

  // Check pointers
  if (NULL == conn) {
    return VSCP_ERROR_ERROR;
  }

  CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return VSCP_ERROR_ERROR;
  }

  if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
    return VSCP_ERROR_ERROR;
  }

  // Record activity
  pSession->setLastActiveTime(time(NULL));

  // switch (((unsigned char) bits) & 0x0F) {

  //   case MG_WEBSOCKET_OPCODE_CONTINUATION:

#ifdef __VSCP_DEBUG_WEBSOCKET_RX
//    syslog(LOG_DEBUG, "Websocket WS1 - opcode = Continuation");
#endif
//       syslog(LOG_DEBUG, "Websocket WS1 - opcode = Continuation");
//     }

//     // Save and concatenate message
//     pSession->m_strConcatenated += std::string(data, len);

//     // if last process is
//     if (1 & bits) {
//       try {
//         if (!ws1_message(conn, pSession, pSession->m_strConcatenated)) {
//           return VSCP_ERROR_ERROR;
//         }
//       }
//       catch (...) {
//         syslog(LOG_ERR, "ws1: Exception occurred ws1_message concat");
//       }
//     }
//     break;

//   // https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
//   case MG_WEBSOCKET_OPCODE_TEXT:
#ifdef __VSCP_DEBUG_WEBSOCKET_RX
//    syslog(LOG_DEBUG, "Websocket WS1 - opcode = text");
#endif
  //       syslog(LOG_DEBUG, "Websocket WS1 - opcode = text[%s]", strWsPkt.c_str());
  //     }
  //     if (1 & bits) {
  //       try {
  //         strWsPkt = std::string(data, len);
  //         if (!ws1_message(conn, pSession, strWsPkt)) {
  //           return VSCP_ERROR_ERROR;
  //         }
  //       }
  //       catch (...) {
  //         syslog(LOG_ERR, "ws1: Exception occurred ws1_message");
  //       }
  //     }
  //     else {
  //       // Store first part
  //       pSession->m_strConcatenated = std::string(data, len);
  //     }
  //     break;

  //   case MG_WEBSOCKET_OPCODE_BINARY:
#ifdef __VSCP_DEBUG_WEBSOCKET
  //       syslog(LOG_DEBUG, "Websocket WS1 - opcode = BINARY");
#endif
  //     break;

  //   case MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE:
#ifdef __VSCP_DEBUG_WEBSOCKET
  //       syslog(LOG_DEBUG, "Websocket WS1 - opcode = Connection close");
#endif
  //     break;

  //   case MG_WEBSOCKET_OPCODE_PING:
#ifdef __VSCP_DEBUG_WEBSOCKET_PING
  //       syslog(LOG_DEBUG, "Websocket WS1 - opcode = Ping");
#endif
  //     if (__VSCP_DEBUG_WEBSOCKET_PING) {
  //       syslog(LOG_DEBUG, "Websocket WS1 - Ping received/Pong sent,");
  //     }
  //     // mg_ws_send(conn, MG_WEBSOCKET_OPCODE_PONG, NULL, 0, WEBSOCKET_OP_TEXT);
  //     break;

  //   case MG_WEBSOCKET_OPCODE_PONG:
#ifdef __VSCP_DEBUG_WEBSOCKET_PONG
  //       syslog(LOG_DEBUG, "Websocket WS2 - Pong received/Pong sent,");
#endif
  //     // mg_ws_send(conn, MG_WEBSOCKET_OPCODE_PING, NULL, 0, WEBSOCKET_OP_TEXT);
  //     break;

  //   default:
  //     break;
  // }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// ws1_message
//

int
CWebSockSrv::ws1_message(struct mg_connection *conn, std::string &strWsPkt)
{
  std::string str;

  // Check pointers
  if (NULL == conn) {
    return false;
  }

  CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;
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
        ws1_command(conn, strWsPkt);
      }
      catch (...) {
        syslog(LOG_ERR, "ws1: Exception occurred ws1_command");
        str = vscp_str_format(("-;C;%d;%s"), (int) WEBSOCK_ERROR_GENERAL, WEBSOCK_STR_ERROR_GENERAL);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      }
      break;

    // Event | 'E' ; head(byte) , vscp_class(unsigned short) ,
    // vscp_type(unsigned
    //              short) , GUID(16*byte), data(0-487 bytes) |
    case 'E': {

      // Must be authorized to do this
      if ((NULL == pSession->getClientItem()) || !pSession->getClientItem()->bAuthenticated) {

        str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORIZED, WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        syslog(LOG_ERR,
               "[Websocket ws1] User [%s] is not "
               "authorized.\n",
               pSession->getClientItem()->m_pUserItem->getUserName().c_str());

        return true;
      }

      // User must be allowed to send events
      if (!(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

        str = vscp_str_format(("-;%d;%s"),
                              (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                              WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);

        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        syslog(LOG_ERR,
               "[Websocket ws1] User [%s] is not "
               "allowed to send events.\n",
               pSession->getClientItem()->m_pUserItem->getUserName().c_str());

        return true; // We still leave channel open
      }

      // Point beyond initial info "E;"
      strWsPkt = vscp_str_right(strWsPkt, strWsPkt.length() - 2);
      vscpEventEx ex;

      try {
        if (vscp_convertStringToEventEx(&ex, strWsPkt)) {

          // If GUID is all null give it GUID of interface
          if (vscp_isGUIDEmpty(ex.GUID)) {
            pSession->getClientItem()->m_guid.writeGUID(ex.GUID);
          }

          // Is this user allowed to send events
          if (!(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);

            mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

            syslog(LOG_ERR,
                   "[Websocket ws1] User [%s] is not "
                   "allowed to send events.\n",
                   pSession->getClientItem()->m_pUserItem->getUserName().c_str());

            return true; // We still leave channel open
          }

          // Is user allowed to send CLASS1.PROTOCOL events
          if ((VSCP_CLASS1_PROTOCOL == ex.vscp_class) && (VSCP_CLASS2_LEVEL1_PROTOCOL == ex.vscp_class) &&
              !(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
            mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

            syslog(LOG_ERR,
                   "[Websocket ws1] User [%s] is not "
                   "authorised to send CLASS1.PROTOCOL events.\n",
                   pSession->getClientItem()->m_pUserItem->getUserName().c_str());

            return true;
          }

          // Is user allowed to send CLASS2.PROTOCOL events
          if ((VSCP_CLASS2_PROTOCOL == ex.vscp_class) &&
              !(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
            mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

            syslog(LOG_ERR,
                   "[Websocket ws1] User [%s] is not "
                   "authorised to send CLASS2.PROTOCOL events.\n",
                   pSession->getClientItem()->m_pUserItem->getUserName().c_str());

            return true;
          }

          // Is user allowed to send CLASS2.HLO events
          if ((VSCP_CLASS2_HLO == ex.vscp_class) &&
              !(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
            mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

            syslog(LOG_ERR,
                   "[Websocket ws1] User [%s] is not "
                   "authorised to send CLASS2.HLO events.\n",
                   pSession->getClientItem()->m_pUserItem->getUserName().c_str());

            return true;
          }

          // Check if this user is allowed to send this event
          if (!pSession->getClientItem()->m_pUserItem->isUserAllowedToSendEvent(ex.vscp_class, ex.vscp_type)) {

            str = vscp_str_format(("-;%d;%s"),
                                  (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                  WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);

            mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

            syslog(LOG_ERR,
                   "[websocket ws1] User [%s] is not allowed to "
                   "send event class=%d type=%d.",
                   pSession->getClientItem()->m_pUserItem->getUserName().c_str(),
                   ex.vscp_class,
                   ex.vscp_type);

            return true; // Keep connection open
          }

          ex.obid = pSession->getClientItem()->m_clientID;
          if (sendEvent(conn, &ex)) {
            mg_ws_send(conn, (const char *) "+;EVENT", 7, WEBSOCKET_OP_TEXT);
#ifdef __VSCP_DEBUG_WEBSOCKET_TX
            syslog(LOG_ERR, "[websocket ws1] Sent ws1 event %s", strWsPkt.c_str());
#endif
          }
          else {
            str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_TX_BUFFER_FULL, WEBSOCK_STR_ERROR_TX_BUFFER_FULL);
            mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
          }
        }
      }
      catch (...) {
        syslog(LOG_ERR, "ws1: Exception occurred send event");
        str = vscp_str_format(("-;E;%d;%s"), (int) WEBSOCK_ERROR_GENERAL, WEBSOCK_STR_ERROR_GENERAL);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
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
CWebSockSrv::ws1_command(struct mg_connection *conn, std::string &strCmd)
{
  std::string str; // Worker string
  std::string strTok;

  // Check pointers
  if (NULL == conn) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return VSCP_ERROR_INVALID_POINTER;
  }

#ifdef __VSCP_DEBUG_WEBSOCKET
  syslog(LOG_ERR, "[Websocket ws1] Command = %s", strCmd.c_str());
#endif

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
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    return VSCP_ERROR_SUCCESS; // We still leave channel open
  }

  // ------------------------------------------------------------------------
  //                                NOOP
  //-------------------------------------------------------------------------

  if (vscp_startsWith(strTok, "NOOP")) {
    mg_ws_send(conn, (const char *) "+;NOOP", 6, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                               CHALLENGE
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "CHALLENGE")) {

    // Send authentication challenge
    if ((NULL == pSession->getClientItem()) || !pSession->getClientItem()->bAuthenticated) {

      // Start authentication
      str = vscp_str_format(("+;AUTH0;%s"), pSession->getSid());
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
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
      if (authentication(conn, strIV, strCrypto)) {
        std::string userSettings;
        pSession->getClientItem()->m_pUserItem->getAsString(userSettings);
        str = vscp_str_format(("+;AUTH1;%s"), (const char *) userSettings.c_str());
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      }
      else {

        str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORIZED, WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
        pSession->getClientItem()->bAuthenticated = false; // Authenticated
      }
    }
    catch (...) {
      syslog(LOG_ERR, "WS1: AUTH failed (syntax)");
      str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    }
  }

  // ------------------------------------------------------------------------
  //                                OPEN
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "OPEN")) {

    // Must be authorised to do this
    if ((NULL == pSession->getClientItem()) || !pSession->getClientItem()->bAuthenticated) {

      str = vscp_str_format(("-;OPEN;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORIZED, WEBSOCK_STR_ERROR_NOT_AUTHORIZED);

      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      return VSCP_ERROR_SUCCESS; // We still leave channel open
    }

    pSession->getClientItem()->m_bOpen = true;
    mg_ws_send(conn, (const char *) "+;OPEN", 6, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                                CLOSE
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "CLOSE")) {
    pSession->getClientItem()->m_bOpen = false;
    mg_ws_send(conn, (const char *) "+;CLOSE", 7, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                             SETFILTER/SF
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "SETFILTER") || vscp_startsWith(strTok, "SF")) {

    unsigned char ifGUID[16];
    memset(ifGUID, 0, 16);

    // Must be authorized to do this
    if ((NULL == pSession->getClientItem()) || !pSession->getClientItem()->bAuthenticated) {

      str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORIZED, WEBSOCK_STR_ERROR_NOT_AUTHORIZED);

      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR, "[Websocket ws1] User/host not authorized to set a filter.");

      return VSCP_ERROR_SUCCESS; // We still leave channel open
    }

    // Check privilege
    if (!(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SETFILTER)) {

      str = vscp_str_format(("-;SF;%d;%s"),
                            (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                            WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);

      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR,
             "[Websocket ws1] User [%s] not "
             "allowed to set a filter.\n",
             pSession->getClientItem()->m_pUserItem->getUserName().c_str());
        return VSCP_ERROR_SUCCESS; // We still leave channel open
    }

    // Get filter
    if (!tokens.empty()) {

      strTok = tokens.front();
      tokens.pop_front();

      pthread_mutex_lock(&pSession->getClientItem()->m_mutexClientInputQueue);
      if (!vscp_readFilterFromString(&pSession->getClientItem()->m_filter, strTok)) {

        str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);

        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        pthread_mutex_unlock(&pSession->getClientItem()->m_mutexClientInputQueue);
        return VSCP_ERROR_SUCCESS;
      }

      pthread_mutex_unlock(&pSession->getClientItem()->m_mutexClientInputQueue);
    }
    else {

      str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);

      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      return VSCP_ERROR_SUCCESS;
    }

    // Get mask
    if (!tokens.empty()) {

      strTok = tokens.front();
      tokens.pop_front();

      pthread_mutex_lock(&pSession->getClientItem()->m_mutexClientInputQueue);
      if (!vscp_readMaskFromString(&pSession->getClientItem()->m_filter, strTok)) {

        str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);

        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        pthread_mutex_unlock(&pSession->getClientItem()->m_mutexClientInputQueue);
        return VSCP_ERROR_SUCCESS;
      }

      pthread_mutex_unlock(&pSession->getClientItem()->m_mutexClientInputQueue);
    }
    else {
      str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);

      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      return VSCP_ERROR_SUCCESS;
    }

    // Positive response
    mg_ws_send(conn, (const char *) "+;SF", 4, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                           CLRQ/CLRQUEUE
  //-------------------------------------------------------------------------

  // Clear the event queue
  else if (vscp_startsWith(strTok, "CLRQUEUE") || vscp_startsWith(strTok, "CLRQ")) {

    // Must be authorized to do this
    if ((NULL == pSession->getClientItem()) || !pSession->getClientItem()->bAuthenticated) {

      str = vscp_str_format(("-;CLRQ;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORIZED, WEBSOCK_STR_ERROR_NOT_AUTHORIZED);

      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR, "[Websocket ws1] User/host not authorized to clear the queue.");

      return VSCP_ERROR_SUCCESS; // We still leave channel open
    }

    std::deque<vscpEvent *>::iterator it;
    pthread_mutex_lock(&pSession->getClientItem()->m_mutexClientInputQueue);

    for (it = pSession->getClientItem()->m_clientInputQueue.begin();
         it != pSession->getClientItem()->m_clientInputQueue.end();
         ++it) {
      vscpEvent *pEvent = pSession->getClientItem()->m_clientInputQueue.front();
      pSession->getClientItem()->m_clientInputQueue.pop_front();
      vscp_deleteEvent_v2(&pEvent);
    }

    pSession->getClientItem()->m_clientInputQueue.clear();
    pthread_mutex_unlock(&pSession->getClientItem()->m_mutexClientInputQueue);

    mg_ws_send(conn, (const char *) "+;CLRQ", 6, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                              VERSION
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "VERSION")) {

    std::string strvalue;

    std::string strResult = ("+;VERSION;");
    // strResult += VSCPD_DISPLAY_VERSION;
    // strResult += (";");
    // strResult += vscp_str_format(("%d.%d.%d.%d"),
    //                              VSCPD_MAJOR_VERSION,
    //                              VSCPD_MINOR_VERSION,
    //                              VSCPD_RELEASE_VERSION,
    //                              VSCPD_BUILD_VERSION);
    // Positive reply
    mg_ws_send(conn, (const char *) strResult.c_str(), strResult.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                              COPYRIGHT
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "COPYRIGHT")) {

    std::string strvalue;

    std::string strResult = ("+;COPYRIGHT;");
    // strResult += VSCPD_COPYRIGHT;

    // Positive reply
    mg_ws_send(conn, (const char *) strResult.c_str(), strResult.length(), WEBSOCKET_OP_TEXT);
  }

  return VSCP_ERROR_SUCCESS;
}

// ----------------------------------------------------------------------------
//                                  WS2
// ----------------------------------------------------------------------------

////////////////////////////////////////////////////////////////////////////////
// ws2_connectHandler
//

// int
// CWebSockSrv::ws2_connectHandler(const struct mg_connection *conn, void *cbdata)
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

#ifdef __VSCP_DEBUG_WEBSOCKET
//     syslog(LOG_ERR, "[Websocket ws2] WS2 Connection: client %s", (reject ? "rejected" : "accepted"));
#endif

//   return reject;
//}

////////////////////////////////////////////////////////////////////////////////
// ws2_closeHandler
//

// void
// CWebSockSrv::ws2_closeHandler(const struct mg_connection *conn, void *cbdata)
// {
//   struct mg_context *ctx    = mg_get_context(conn);
//   CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;

//   if (NULL == conn) {
//     return;
//   }
//   if (NULL == pSession) {
//     return;
//   }
//   if (pSession->getConn() != conn) {
//     return;
//   }
//   if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
//     return;
//   }

//   mg_lock_context(ctx);

//   // Record activity
//   pSession->lastActiveTime = time(NULL);

//   pSession->getConnState() = WEBSOCK_CONN_STATE_NULL;
//   pSession->getConn()       = NULL;
//   m_clientList.removeClient(pSession->getClientItem());
//   pSession->getClientItem() = NULL;

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
// CWebSockSrv::ws2_readyHandler(struct mg_connection *conn, void *cbdata)
// {
//   CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;

//   // Check pointers
//   if (NULL == conn) {
//     return;
//   }

//   if (NULL == pSession) {
//     return;
//   }

//   if (pSession->getConn() != conn) {
//     return;
//   }

//   if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
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
//   mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

//   pSession->getConnState() = WEBSOCK_CONN_STATE_DATA;
// }

////////////////////////////////////////////////////////////////////////////////
// ws2_dataHandler
//

int
CWebSockSrv::ws2_dataHandler(struct mg_connection *conn, int bits, char *data, size_t len, void *cbdata)
{
  std::string strWsPkt;

  // Check pointers
  if (NULL == conn) {
    return VSCP_ERROR_ERROR;
  }

  CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return VSCP_ERROR_ERROR;
  }

  if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
    return VSCP_ERROR_ERROR;
  }

  // Record activity
  pSession->setLastActiveTime(time(NULL));

  //   switch (((unsigned char) bits) & 0x0F) {

  //     case MG_WEBSOCKET_OPCODE_CONTINUATION:

  // #ifdef __VSCP_DEBUG_WEBSOCKET
  //       syslog(LOG_DEBUG, "Websocket WS2 - opcode = Continuation");
  // #endif

  //       // Save and concatenate message
  //       pSession->m_strConcatenated += std::string(data, len);

  //       // if last process is
  //       if (1 & bits) {
  //         try {
  //           if (!ws2_message(conn, pSession, pSession->m_strConcatenated)) {
  //             return VSCP_ERROR_ERROR;
  //           }
  //         }
  //         catch (...) {
  //           syslog(LOG_ERR, "ws1: Exception occurred ws2_message concat");
  //         }
  //       }
  //       break;

  //     // https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
  //     case MG_WEBSOCKET_OPCODE_TEXT:

  // #ifdef __VSCP_DEBUG_WEBSOCKET
  //       syslog(LOG_DEBUG, "Websocket WS2 - opcode = Text [%s]", strWsPkt.c_str());
  // #endif

  //       if (1 & bits) {
  //         try {
  //           strWsPkt = std::string(data, len);
  //           if (!ws2_message(conn, pSession, strWsPkt)) {
  //             return VSCP_ERROR_ERROR;
  //           }
  //         }
  //         catch (...) {
  //           syslog(LOG_ERR, "ws1: Exception occurred ws2_message");
  //         }
  //       }
  //       else {
  //         // Store first part
  //         pSession->m_strConcatenated = std::string(data, len);
  //       }
  //       break;

  //     case MG_WEBSOCKET_OPCODE_BINARY:
  // #ifdef __VSCP_DEBUG_WEBSOCKET
  //       syslog(LOG_DEBUG, "Websocket WS2 - opcode = BINARY");
  // #endif
  //       break;

  //     case MG_WEBSOCKET_OPCODE_CONNECTION_CLOSE:
  // #ifdef __VSCP_DEBUG_WEBSOCKET
  //       syslog(LOG_DEBUG, "Websocket WS2 - Connection close");
  // #endif
  //       break;

  //     case MG_WEBSOCKET_OPCODE_PING:
  // #ifdef __VSCP_DEBUG_WEBSOCKET_PONG
  //       syslog(LOG_DEBUG, "Websocket WS2 - Ping received/Pong sent,");
  // #endif
  //       // mg_ws_send(conn, MG_WEBSOCKET_OPCODE_PONG, data, len, WEBSOCKET_OP_TEXT);
  //       break;

  //     case MG_WEBSOCKET_OPCODE_PONG:
  // #ifdef __VSCP_DEBUG_WEBSOCKET_PING
  //       syslog(LOG_DEBUG, "Websocket WS2 - Pong received/Ping sent,");
  // #endif
  //       // mg_ws_send(conn, MG_WEBSOCKET_OPCODE_PING, data, len, WEBSOCKET_OP_TEXT);
  //       break;

  //     default:
  //       break;
  //   }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// ws2_message
//

int
CWebSockSrv::ws2_message(struct mg_connection *conn, std::string &strWsPkt)
{
  w2msg msg;
  std::string str;
  json json_obj; // Command obj, event obj etc

  // Check pointers
  if (NULL == conn) {
    return false;
  }

  CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;
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
              return ws2_command(conn, strCmd, it.value());
            }
          }

          std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                            strCmd.c_str(),
                                            WEBSOCK_ERROR_PARSE_FORMAT,
                                            WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          // No arg found
          syslog(LOG_ERR, "Failed to parse ws2 websocket command object %s", strWsPkt.c_str());
          return false;
        }
        catch (...) {
          std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                            strCmd.c_str(),
                                            WEBSOCK_ERROR_PARSE_FORMAT,
                                            WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

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
              if ((NULL == pSession->getClientItem()) || !pSession->getClientItem()->bAuthenticated) {

                str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                      "EVENT",
                                      (int) WEBSOCK_ERROR_NOT_AUTHORIZED,
                                      WEBSOCK_STR_ERROR_NOT_AUTHORIZED);

                mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                syslog(LOG_ERR,
                       "[Websocket ws2] User [%s] is not "
                       "allowed to login.\n",
                       pSession->getClientItem()->m_pUserItem->getUserName().c_str());

                return false; // 'false' - Drop connection
              }

              vscpEventEx ex;
              if (vscp_convertJSONToEventEx(&ex, str)) {

                // If GUID is all null give it GUID of interface
                if (vscp_isGUIDEmpty(ex.GUID)) {
                  pSession->getClientItem()->m_guid.writeGUID(ex.GUID);
                }

                // Is this user allowed to send events
                if (!(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  syslog(LOG_ERR,
                         "[Websocket ws2] User [%s] is not "
                         "allowed to send events.\n",
                         pSession->getClientItem()->m_pUserItem->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS1.PROTOCOL
                // events
                if ((VSCP_CLASS1_PROTOCOL == ex.vscp_class) && (VSCP_CLASS2_LEVEL1_PROTOCOL == ex.vscp_class) &&
                    !(pSession->getClientItem()->m_pUserItem->getUserRights() &
                      VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  syslog(LOG_ERR,
                         "[Websocket ws2] User [%s] is not "
                         "authorised to send CLASS1.PROTOCOL "
                         "events.\n",
                         pSession->getClientItem()->m_pUserItem->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS2.PROTOCOL
                // events
                if ((VSCP_CLASS2_PROTOCOL == ex.vscp_class) &&
                    !(pSession->getClientItem()->m_pUserItem->getUserRights() &
                      VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  syslog(LOG_ERR,
                         "[Websocket ws2] User [%s] is not "
                         "authorized to send CLASS2.PROTOCOL "
                         "events.\n",
                         pSession->getClientItem()->m_pUserItem->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS2.HLO events
                if ((VSCP_CLASS2_HLO == ex.vscp_class) &&
                    !(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  syslog(LOG_ERR,
                         "[Websocket ws2] User [%s] is not "
                         "authorised to send CLASS2.HLO "
                         "events.\n",
                         pSession->getClientItem()->m_pUserItem->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Check if this user is allowed to send this
                // event
                if (!pSession->getClientItem()->m_pUserItem->isUserAllowedToSendEvent(ex.vscp_class, ex.vscp_type)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  syslog(LOG_ERR,
                         "websocket] User [%s] is not allowed to "
                         "send event class=%d type=%d.",
                         pSession->getClientItem()->m_pUserItem->getUserName().c_str(),
                         ex.vscp_class,
                         ex.vscp_type);

                  return true; // 'true' leave connection open
                }

                ex.obid = pSession->getClientItem()->m_clientID;
                if (sendEvent(conn, &ex)) {

                  str = vscp_str_format(WS2_POSITIVE_RESPONSE, "EVENT", "null");
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

#ifdef __VSCP_DEBUG_WEBSOCKET_TX
                  syslog(LOG_ERR, "Sent ws2 event %s", strWsPkt.c_str());
#endif
                }
                else {

                  str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        "EVENT",
                                        (int) WEBSOCK_ERROR_TX_BUFFER_FULL,
                                        WEBSOCK_STR_ERROR_TX_BUFFER_FULL);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
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
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

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
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

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
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

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
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          syslog(LOG_ERR, "Failed to parse ws2 websocket variable object %s", strWsPkt.c_str());
          return true; // 'true' leave connection open
        }
      }
      else {
        std::string str =
          vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_UNKNOWN_TYPE, WEBSOCK_STR_ERROR_UNKNOWN_TYPE);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        // This is a type we do not recognize
        syslog(LOG_ERR, "Unknown ws2 websocket type %s", strWsPkt.c_str());
        return true; // 'true' leave connection open
      }
    }
  }
  catch (...) {
    std::string str =
      vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_UNKNOWN_TYPE, WEBSOCK_STR_ERROR_UNKNOWN_TYPE);
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

    syslog(LOG_ERR, "Failed to parse ws2 websocket command %s", strWsPkt.c_str());
    return true; // 'true' leave connection open
  }

  return true;
}

////////////////////////////////////////////////////////////////////////////////
// ws2_command
//

int
CWebSockSrv::ws2_command(struct mg_connection *conn, std::string &strCmd, json &jsonObj)
{
  // Check pointers
  if (NULL == conn) {
    return false;
  }

  CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return false;
  }

#ifdef __VSCP_DEBUG_WEBSOCKET
  syslog(LOG_DEBUG, "[Websocket ws2] Command = %s", strCmd.c_str());
#endif

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
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

    syslog(LOG_ERR, "[Websocket ws2] SETFILTER parse error = %s", jsonObj.dump().c_str());

    return false;
  }

  // ------------------------------------------------------------------------
  //                                NOOP
  //-------------------------------------------------------------------------

  if ("NOOP" == strCmd) {

    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, "NOOP", "null");
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                               CHALLENGE
  //-------------------------------------------------------------------------

  else if ("CHALLENGE" == strCmd) {

    // Send authentication challenge
    if ((NULL == pSession->getClientItem()) || !pSession->getClientItem()->bAuthenticated) {

      // Start authentication
      std::string strSessionId = vscp_str_format("{\"sid\": \"%s\"}", pSession->getSid());
      std::string str          = vscp_str_format(WS2_POSITIVE_RESPONSE, "CHALLENGE", strSessionId);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
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
    if (authentication(conn, strIV, strCrypto)) {
      std::string userSettings;
      pSession->getClientItem()->m_pUserItem->getAsString(userSettings);
      str = vscp_str_format(WS2_POSITIVE_RESPONSE, "AUTH", "null");
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    }
    else {

      str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                            "AUTH",
                            (int) WEBSOCK_ERROR_NOT_AUTHORIZED,
                            WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      pSession->getClientItem()->bAuthenticated = false; // Authenticated
    }
  }

  // ------------------------------------------------------------------------
  //                                OPEN
  //-------------------------------------------------------------------------

  else if ("OPEN" == strCmd) {

    // Must be authorized to do this
    if ((NULL == pSession->getClientItem()) || !pSession->getClientItem()->bAuthenticated) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        "OPEN",
                                        (int) WEBSOCK_ERROR_NOT_AUTHORIZED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      return false; // We still leave channel open
    }

    pSession->getClientItem()->m_bOpen = true;
    std::string str                    = vscp_str_format(WS2_POSITIVE_RESPONSE, "OPEN", "null");
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                                CLOSE
  //-------------------------------------------------------------------------

  else if ("CLOSE" == strCmd) {
    pSession->getClientItem()->m_bOpen = false;
    std::string str                    = vscp_str_format(WS2_POSITIVE_RESPONSE, "CLOSE", "null");
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                             SETFILTER/SF
  //-------------------------------------------------------------------------

  else if (("SETFILTER" == strCmd) || ("SF" == strCmd)) {

    std::string strFilter;
    unsigned char ifGUID[16];
    memset(ifGUID, 0, 16);

    // Must be authorized to do this
    if ((NULL == pSession->getClientItem()) || !pSession->getClientItem()->bAuthenticated) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_AUTHORIZED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR, "[Websocket w2] User/host is not authorised to set a filter.");

      return false; // We still leave channel open
    }

    // Check privilege
    if (!(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_SETFILTER)) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                        WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR,
             "[Websocket w2] User [%s] is not "
             "allowed to set a filter.\n",
             pSession->getClientItem()->m_pUserItem->getUserName().c_str());
      return false; // We still leave channel open
    }

    // Get filter
    if (!argmap.empty()) {

      strFilter = jsonObj.dump();

      pthread_mutex_lock(&pSession->getClientItem()->m_mutexClientInputQueue);
      if (!vscp_readFilterMaskFromJSON(&pSession->getClientItem()->m_filter, strFilter)) {

        std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                          strCmd.c_str(),
                                          (int) WEBSOCK_ERROR_SYNTAX_ERROR,
                                          WEBSOCK_STR_ERROR_SYNTAX_ERROR);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        syslog(LOG_ERR, "[Websocket w2] Set filter syntax error. [%s]", strFilter.c_str());

        pthread_mutex_unlock(&pSession->getClientItem()->m_mutexClientInputQueue);
        return false;
      }

      pthread_mutex_unlock(&pSession->getClientItem()->m_mutexClientInputQueue);
    }
    else {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_SYNTAX_ERROR,
                                        WEBSOCK_STR_ERROR_SYNTAX_ERROR);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR, "[Websocket w2] Set filter syntax error. [%s]", strFilter.c_str());

      return false;
    }

    // Positive response
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), "null");
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                           CLRQ/CLRQUEUE
  //-------------------------------------------------------------------------

  // Clear the event queue
  else if (("CLRQUEUE" == strCmd) || ("CLRQ" == strCmd)) {

    // Must be authorised to do this
    if ((NULL == pSession->getClientItem()) || !pSession->getClientItem()->bAuthenticated) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_AUTHORIZED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORIZED);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      syslog(LOG_ERR, "[Websocket w2] User/host is not authorised to clear the queue.");

      return false; // We still leave channel open
    }

    std::deque<vscpEvent *>::iterator it;
    pthread_mutex_lock(&pSession->getClientItem()->m_mutexClientInputQueue);

    for (it = pSession->getClientItem()->m_clientInputQueue.begin();
         it != pSession->getClientItem()->m_clientInputQueue.end();
         ++it) {
      vscpEvent *pEvent = pSession->getClientItem()->m_clientInputQueue.front();
      pSession->getClientItem()->m_clientInputQueue.pop_front();
      vscp_deleteEvent_v2(&pEvent);
    }

    pSession->getClientItem()->m_clientInputQueue.clear();
    pthread_mutex_unlock(&pSession->getClientItem()->m_mutexClientInputQueue);

    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), "null");
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                              VERSION
  //-------------------------------------------------------------------------

  else if (("VERSION" == strCmd) || ("VER" == strCmd)) {

    // std::string strvalue;
    std::string strResult;
    // strResult = vscp_str_format("{ \"version\" : \"%d.%d.%d-%d\" }",
    //                             VSCPD_MAJOR_VERSION,
    //                             VSCPD_MINOR_VERSION,
    //                             VSCPD_RELEASE_VERSION,
    //                             VSCPD_BUILD_VERSION);
    // Positive reply
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), strResult.c_str());
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                              COPYRIGHT
  //-------------------------------------------------------------------------

  else if ("COPYRIGHT" == strCmd) {

    std::string strvalue;

    std::string strResult = ("{ \"copyright\" : \"");
    //strResult += VSCPD_COPYRIGHT;
    strResult += "\" }";

    // Positive reply
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), strResult.c_str());
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
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
CWebSockSrv::ws2_xcommand(struct mg_connection *conn, std::string &strCmd)
{
  std::string str; // Worker string
  std::string strTok;

  // Check pointers
  if (NULL == conn) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;
  if (NULL == pSession) {
    return VSCP_ERROR_INVALID_POINTER;
  }

#ifdef __VSCP_DEBUG_WEBSOCKET
  syslog(LOG_ERR, "[Websocket ws2] Command = %s", strCmd.c_str());
#endif

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
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    return VSCP_ERROR_SUCCESS;
  }

  // ------------------------------------------------------------------------
  //                                NOOP
  //-------------------------------------------------------------------------

  if (vscp_startsWith(strTok, "NOOP")) {
    mg_ws_send(conn, (const char *) "+;NOOP", 6, WEBSOCKET_OP_TEXT);
  }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// websocket_post_incomingEvent
//

int
CWebSockSrv::websock_post_incomingEvents(void)
{
  //   pthread_mutex_lock(&gpobj->m_mutex_websocketSession);

  //   std::list<websock_session *>::iterator iter;
  //   for (iter = gpobj->m_websocketSessions.begin(); iter != gpobj->m_websocketSessions.end(); ++iter) {

  //     websock_session *pSession = *iter;
  //     if (NULL == pSession) {
  //       continue;
  //     }

  //     // Should be a client item... hmm.... client disconnected
  //     if (NULL == pSession->getClientItem()) {
  //       continue;
  //     }

  //     if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED)
  //       continue;

  //     if (NULL == pSession->getConn())
  //       continue;

  //     if (pSession->getClientItem()->m_bOpen && pSession->getClientItem()->m_clientInputQueue.size()) {

  //       vscpEvent *pEvent;
  //       pthread_mutex_lock(&pSession->getClientItem()->m_mutexClientInputQueue);
  //       pEvent = pSession->getClientItem()->m_clientInputQueue.front();
  //       pSession->getClientItem()->m_clientInputQueue.pop_front();
  //       pthread_mutex_unlock(&pSession->getClientItem()->m_mutexClientInputQueue);
  //       if (NULL != pEvent) {

  //         // Run event through filter
  //         if (vscp_doLevel2Filter(pEvent, &pSession->getClientItem()->m_filter)) {

  //           // User must be authorized to receive events
  //           if (!(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
  //             continue;
  //           }

  //           std::string str;
  //           if (vscp_convertEventToString(str, pEvent)) {

  // #ifdef __VSCP_DEBUG_WEBSOCKET_RX
  //             syslog(LOG_DEBUG, "Received ws event %s", str.c_str());
  // #endif

  //             // Write it out
  //             if (WS_TYPE_1 == pSession->m_wstypes) {
  //               str = ("E;") + str;
  //               //mg_websocket_write(pSession->getConn(), (const char *) str.c_str(), str.length());
  //             }
  //             else if (WS_TYPE_2 == pSession->m_wstypes) {
  //               std::string strEvent;
  //               vscp_convertEventToJSON(strEvent, pEvent);
  //               std::string str = vscp_str_format(WS2_EVENT, strEvent.c_str());
  //               //mg_websocket_write(pSession->getConn(), (const char *) str.c_str(), str.length());
  //             }
  //           }
  //         }

  //         // Remove the event
  //         vscp_deleteEvent_v2(&pEvent);

  //       } // Valid pEvent pointer

  //     } // events available

  //   } // for

  //   pthread_mutex_unlock(&gpobj->m_mutex_websocketSession);
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventAllClients
//

void
CWebSockSrv::sendEventAllClients(const vscpEvent *pEvent)
{
  if (NULL == pEvent) {
    return;
  }

  // pthread_mutex_lock(&gpobj->m_mutex_websocketSession);

  //   std::list<websock_session *>::iterator iter;
  //   for (iter = gpobj->m_websocketSessions.begin(); iter != gpobj->m_websocketSessions.end(); ++iter) {

  //     websock_session *pSession = *iter;
  //     if (NULL == pSession) {
  //       continue;
  //     }

  //     // Should be a client item... hmm.... client disconnected
  //     if (NULL == pSession->getClientItem()) {
  //       continue;
  //     }

  //     if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED)
  //       continue;

  //     if (NULL == pSession->getConn())
  //       continue;

  //     if (pSession->getClientItem()->m_bOpen) {

  //       // Run event through filter
  //       if (vscp_doLevel2Filter(pEvent, &pSession->getClientItem()->m_filter)) {

  //         // User must be authorized to receive events
  //         if (!(pSession->getClientItem()->m_pUserItem->getUserRights() & VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
  //           continue;
  //         }

  //         std::string str;
  //         if (vscp_convertEventToString(str, pEvent)) {

  // #ifdef __VSCP_DEBUG_WEBSOCKET_RX
  //           syslog(LOG_DEBUG, "Received ws event %s", str.c_str());
  // #endif

  //           // Write it out
  //           if (WS_TYPE_1 == pSession->m_wstypes) {
  //             str = ("E;") + str;
  //             //mg_websocket_write(pSession->getConn(), (const char *) str.c_str(), str.length());
  //           }
  //           else if (WS_TYPE_2 == pSession->m_wstypes) {
  //             std::string strEvent;
  //             vscp_convertEventToJSON(strEvent, pEvent);
  //             std::string str = vscp_str_format(WS2_EVENT, strEvent.c_str());
  //             //mg_websocket_write(pSession->getConn(), (const char *) str.c_str(), str.length());
  //           }
  //         }
  //       }

  //     } // events available

  //   } // for

  // pthread_mutex_unlock(&gpobj->m_mutex_websocketSession);
}

/////////////////////////////////////////////////////////////////////////////
// generateSessionId
//

bool
CWebSockSrv::generateSessionId(const char *pKey, char *psid)
{
  char buf[8193];

  // Check pointers
  if (NULL == pKey) {
    return false;
  }
  if (NULL == psid) {
    return false;
  }
  // Check key length
  if (strlen(pKey) > 256) {
    return false;
  }

  // Generate a random session ID
  time_t t;
  t = time(NULL);
  snprintf(buf,
           sizeof(buf),
           "__%s_%X%X%X%X_be_hungry_stay_foolish_%X%X",
           pKey,
           (unsigned int) rand(),
           (unsigned int) rand(),
           (unsigned int) rand(),
           (unsigned int) t,
           (unsigned int) rand(),
           1337);

  vscp_md5(psid, (const unsigned char *) buf, strlen(buf));

  return true;
}

/////////////////////////////////////////////////////////////////////////////
// readEncryptionKey
//

bool
CWebSockSrv::readEncryptionKey(const std::string &path)
{
  // TODO Key is in session object
  // try {
  //   std::ifstream in(path, std::ifstream::in);
  //   std::stringstream strStream;
  //   strStream << in.rdbuf();
  //   return vscp_hexStr2ByteArray(m_key, 32, strStream.str().c_str());
  // }
  // catch (...) {
  //   spdlog::error("Failed to read encryption key file [%s]", getKeyPath().c_str());
  //   return false;
  // }

  return true;
}

///////////////////////////////////////////////////////////////////////////////
// timer_fn
//
// Timer function - recreate client connection if it is closed
//

static void
timer_fn(void *arg)
{
  // struct mg_mgr *mgr = (struct mg_mgr *) arg;
  // if (c_res.c == NULL) {
  //   c_res.i = 0;
  //   c_res.c = mg_connect(mgr, s_conn, cfn, &c_res);
  //   MG_INFO(("CLIENT %s", c_res.c ? "connecting" : "failed"));
  // }
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
server_event_handler(struct mg_connection *conn, int mgev, void *ev_data)
{
  // // Check pointers
  // if (NULL == conn) {
  //   syslog(LOG_ERR, "Communication context is NULL.");
  //   return;
  // }

  // if (NULL == ev_data) {
  //   syslog(LOG_ERR, "server_event_handler: ev_data is NULL.");
  //   return;
  // }

  // struct mg_tls_opts *tls_opts = NULL;
  // struct mg_str s_ca_path      = mg_str(m_tls_ca_file);
  // struct mg_str s_cert_path    = mg_str(m_tls_ca_file);
  // struct mg_str s_key_path     = mg_str(m_tls_key_file);

  // CWebSockSrv *pWebSockSrv = (CWebSockSrv *) mg_get_user_connection_data(conn);
  // if (NULL == pWebSockSrv) {
  //   syslog(LOG_ERR, "server_event_handler: Invalid CWebSockSrv pointer.");
  //   return;
  // }

  // if (mgev == MG_EV_OPEN) {
  //   conn->is_hexdumping = 1;
  // }
  // else if (conn->is_tls && mgev == MG_EV_ACCEPT) {
  //   struct mg_str ca        = mg_file_read(&mg_fs_posix, s_ca_path.buf);
  //   struct mg_str cert      = mg_file_read(&mg_fs_posix, s_cert_path.buf);
  //   struct mg_str key       = mg_file_read(&mg_fs_posix, s_key_path.buf);
  //   struct mg_tls_opts opts = { .ca = ca, .cert = cert, .key = key };
  //   mg_tls_init(conn, &opts);
  // }
  // else if (mgev == MG_EV_HTTP_MSG) {
  //   struct mg_http_message *hm = (struct mg_http_message *) ev_data;
  //   if (mg_match(hm->uri, mg_str("/ws1"), NULL)) {
  //     // Upgrade to websocket (ws1 protocol). From now on, a connection is a full-duplex
  //     // Websocket connection, which will receive MG_EV_WS_MSG events.
  //     mg_ws_upgrade(conn, hm, NULL);

  //     CWebSockSession *pSession = new CWebSockSession();
  //     if (NULL == pSession) {
  //       syslog(LOG_ERR, "server_event_handler: Failed to create CWebSockSession instance.");
  //       mg_http_reply(con, 500, "", "Internal Server Error\n");
  //       return;
  //     }
  //     pSession->m_wstypes = WS_TYPE_1;
  //     conn->pfn_data      = pSession; // Set session pointer in connection

  //     // Send AUTH start message
  //     ws1_readyHandler(conn, pSession);
  //   }
  //   else if (mg_match(hm->uri, mg_str("/ws2"), NULL)) {
  //     // Upgrade to websocket (ws2 protocol). From now on, a connection is a full-duplex
  //     // Websocket connection, which will receive MG_EV_WS_MSG events.
  //     mg_ws_upgrade(conn, hm, NULL);

  //     CWebSockSession *pSession = new CWebSockSession();
  //     if (NULL == pSession) {
  //       syslog(LOG_ERR, "server_event_handler: Failed to create CWebSockSession instance.");
  //       mg_http_reply(conn, 500, "", "Internal Server Error\n");
  //       return;
  //     }
  //     pSession->m_wstypes = WS_TYPE_2;
  //     conn->pfn_data      = pSession; // Set session pointer in connection

  //     // Send AUTH start message
  //     ws2_readyHandler(conn, pSession);
  //   }
  //   else if (mg_match(hm->uri, mg_str("/rest"), NULL)) {
  //     // Serve REST response
  //     mg_http_reply(conn, 200, "", "{\"result\": %d}\n", 123);
  //   }
  //   else {
  //     // Serve static files
  //     struct mg_http_serve_opts opts = { .root_dir = s_web_root };
  //     mg_http_serve_dir(conn, ev_data, &opts);
  //   }
  // }
  // else if (mgev == MG_EV_WS_MSG) {
  //   // Got websocket frame. Received data is wm->data. Echo it back!
  //   struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
  //   mg_ws_send(conn, wm->data.buf, wm->data.len, WEBSOCKET_OP_TEXT);
  // }
  // else if (mgev == MG_EV_WAKEUP) {
  //   struct mg_str *data = (struct mg_str *) ev_data;
  //   // Broadcast message to all connected websocket clients,
  //   // except the one that sent it.
  //   if (data == NULL || data->len == 0) {
  //     syslog(LOG_ERR, "server_event_handler: No data to send.");
  //     return;
  //   }
  //   syslog(LOG_INFO, "Broadcasting message: %.*s", (int) data->len, data->buf);

  //   // Iterate over all connections in the manager
  //   // and send the message to all websocket connections.
  //   // Note: This is a simple broadcast, you may want to implement
  //   // more sophisticated logic to filter which connections should receive the message.
  //   // For example, you might want to send only to connections that have a specific label or
  //   // that are subscribed to a specific topic.

  //   // Traverse over all connections
  //   for (struct mg_connection *wc = conn->mgr->conns; wc != NULL; wc = wc->next) {
  //     // Send to all other connections not to self
  //     if ((wc->id != conn->id) && wc->is_websocket) {
  //       mg_ws_send(wc, data->buf, data->len, WEBSOCKET_OP_TEXT);
  //     }
  //   }
  //   else if (mgev == MG_EV_CLOSE)
  //   {
  //     // Connection is closed, free resources
  //     if (conn->is_tls) {
  //       mg_tls_free(conn);
  //     }

  //     if (nullptr != conn->pfn_data) {
  //       // Free the session data
  //       CWebSockSession *pSession = (CWebSockSession *) conn->pfn_data;
  //       delete pSession;
  //       conn->pfn_data = NULL; // Clear pointer to avoid dangling pointer
  //     }

  //     // syslog(LOG_INFO, "Connection closed: %s", conn->label);
  //   }
  //   // else if (mgev == MG_EV_TIMER)
  //   // {
  //   //   // Timer event, do nothing
  //   // }
  //   else
  //   {
  //     syslog(LOG_ERR, "Unhandled event %d", mgev);
  //   }
  // }
}

///////////////////////////////////////////////////////////////////////////////
// websockListenThread
//

static void *
websockListenThread(void *pData)
{
  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) pData;
  if (NULL == pWebSockSrv) {
    syslog(LOG_ERR, "websockListenThread: Invalid CWebSockSrv pointer.");
    return NULL;
  }

  struct mg_mgr mgr; // Event manager
  mg_mgr_init(&mgr); // Initialise event manager
  printf("Starting WS listener on %s/websocket\n", pWebSockSrv->getUrl().c_str());

  // Create HTTP listener
  mg_http_listen(&mgr, pWebSockSrv->getUrl().c_str(), server_event_handler, NULL);

  while (!pWebSockSrv->m_bQuit) {
    mg_mgr_poll(&mgr, 100); // Poll for events
  }

  mg_mgr_free(&mgr);
  return 0;
}