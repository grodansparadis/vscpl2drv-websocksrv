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

#ifdef WIN32
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
// _WINSOCK_DEPRECATED_NO_WARNINGS is already defined by mongoose.h
// #ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
// #define _WINSOCK_DEPRECATED_NO_WARNINGS
// #endif
#include "StdAfx.h"
#include <pch.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <algorithm>

#ifdef WIN32
#include <windows.h>
#else
#include <arpa/inet.h>
#include <errno.h>
#ifdef __linux__
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#endif
#ifdef __APPLE__
#include <net/ethernet.h>
#include <sys/sockio.h>
#endif
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <pthread.h>
#ifndef WIN32
#include <semaphore.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mongoose.h>
#include <expat.h>

#include <vscp.h>
#include <vscp-aes.h>
#include <vscp-debug.h>
#include <vscphelper.h>

#include "version.h"
#include "websocksrv.h"

#include <mustache.hpp>
#include <nlohmann/json.hpp> // Needs C++11  -std=c++11

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#ifdef WIN32
// Windows socket initialization will be done in constructor
#endif

/*!
  Define the version for the ws1 protocol supported
  by this driver
*/
#define VSCP_WS1_PROTOCOL_VERSION         1
#define VSCP_WS1_PROTOCOL_MINOR_VERSION   0
#define VSCP_WS1_PROTOCOL_RELEASE_VERSION 0
#define VSCP_WS1_PROTOCOL_BUILD_VERSION   0

/*!
  Define the version for the ws1 protocol supported
  by this driver
*/
#define VSCP_WS2_PROTOCOL_VERSION         1
#define VSCP_WS2_PROTOCOL_MINOR_VERSION   0
#define VSCP_WS2_PROTOCOL_RELEASE_VERSION 0
#define VSCP_WS2_PROTOCOL_BUILD_VERSION   0

// Websocket flags
#define WEBSOCKET_OP_FINAL 0x80

// https://github.com/nlohmann/json
using json = nlohmann::json;

using namespace kainjow::mustache;

// Forward declaration
static void *
websockWorkerThread(void *pData);

//////////////////////////////////////////////////////////////////////
// CWebSockSession
//

CWebSockSession::CWebSockSession(void)
{
  setWsType(WS_TYPE_1); // ws1 is default
  m_conn_state = WEBSOCK_CONN_STATE_NULL;
  memset(m_key, 0, 33);
  memset(m_sid, 0, 33);
  m_version      = 0;
  lastActiveTime = 0;
  m_conn         = nullptr;
  m_strConcatenated.clear();
  memset(m_key, 0, sizeof(m_key)); // No encryption key yet

  generateSid(); // Generate session ID

  vscp_clearVSCPFilter(&m_filter); // Clear filter

  // This is an inactive client
  m_bOpen = false;

  setAuthenticated(false); // Not authenticated in yet

  // Initialise semaphores
#ifdef WIN32
  m_semInputQueue = CreateSemaphore(NULL, 0, MAX_ITEMS_IN_QUEUE, NULL);
#else
  sem_init(&m_semInputQueue, 0, 0);
#endif

  // Initialise mutexes
  pthread_mutex_init(&m_mutexInputQueue, NULL);
};

CWebSockSession::~CWebSockSession(void)
{
  // Clear the input queue
  pthread_mutex_lock(&m_mutexInputQueue);
  for (auto it = m_inputQueue.begin(); it != m_inputQueue.end(); ++it) {
    vscpEvent *pEvent = *it;
    if (NULL != pEvent) {
      vscp_deleteEvent(pEvent);
    }
  }
  m_inputQueue.clear();
  pthread_mutex_unlock(&m_mutexInputQueue);

#ifdef WIN32
  CloseHandle(m_semInputQueue);
#else
  sem_destroy(&m_semInputQueue);
#endif
  pthread_mutex_destroy(&m_mutexInputQueue);
};

////////////////////////////////////////////////////////////////////////////////
// addToInputQueue
//

int
CWebSockSession::addToInputQueue(const vscpEvent *pEvent)
{
  // Check pointer
  if (NULL == pEvent) {
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Make copy of event
  vscpEvent *pEventCopy = new vscpEvent;
  if (NULL == pEventCopy) {
    return VSCP_ERROR_MEMORY;
  }
  vscp_copyEvent(pEventCopy, pEvent);

  // Lock the input queue
  pthread_mutex_lock(&m_mutexInputQueue);

  // Add event to input queue
  m_inputQueue.push_back(pEventCopy);

  // Post semaphore
#ifdef WIN32
  ReleaseSemaphore(m_semInputQueue, 1, NULL);
#else
  sem_post(&m_semInputQueue);
#endif

  // Unlock the input queue
  pthread_mutex_unlock(&m_mutexInputQueue);

  return VSCP_ERROR_SUCCESS;
};

////////////////////////////////////////////////////////////////////////////////
// generateSid
//

void
CWebSockSession::generateSid(void)
{
  // Generate the sid
  unsigned char iv[16];
  char hexiv[33];
  getRandomIV(iv, 16); // Generate 16 random bytes
  memset(hexiv, 0, sizeof(hexiv));
  vscp_byteArray2HexStr(hexiv, iv, 16);

  // Make upper case
  for (int i = 0; i < 32; i++) {
    hexiv[i] = toupper(hexiv[i]);
  }
  memset(m_sid, 0, sizeof(m_sid));
  memcpy(m_sid, hexiv, 32);
}

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
  memset(&m_ex, 0, sizeof(vscpEventEx));
};

////////////////////////////////////////////////////////////////////////////////////
// Destructor
//

w2msg::~w2msg(void)
{
  ;
}

// ----------------------------------------------------------------------------

//////////////////////////////////////////////////////////////////////
// CWebSockSrv
//////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
// Constructor
//

CWebSockSrv::CWebSockSrv(void)
{
  m_bQuit = false;

#ifdef WIN32
  // Initialize Windows sockets
  WSADATA wsaData;
  int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult != 0) {
    spdlog::error("WSAStartup failed: {0}", iResult);
  }
#endif

  vscp_clearVSCPFilter(&m_rxfilter); // Accept all events

#ifdef WIN32
  m_websockWorkerThread = NULL;
#else
  m_websockWorkerThread = 0;
#endif
  m_bDebug             = false;
  m_maxClientQueueSize = MAX_ITEMS_IN_QUEUE;

// Initialise semaphores
#ifdef WIN32
  m_semSendQueue    = CreateSemaphore(NULL, 0, MAX_ITEMS_IN_QUEUE, NULL);
  m_semReceiveQueue = CreateSemaphore(NULL, 0, MAX_ITEMS_IN_QUEUE, NULL);
#else
  sem_init(&m_semSendQueue, 0, 0);
  sem_init(&m_semReceiveQueue, 0, 0);
#endif

  // Initialise mutex
  pthread_mutex_init(&m_mutexSendQueue, NULL);
  pthread_mutex_init(&m_mutexReceiveQueue, NULL);
  pthread_mutex_init(&m_mutex_websocketSession, NULL);

  pthread_mutex_init(&m_mutex_UserList, NULL);

  // Init pool
  spdlog::init_thread_pool(8192, 1);

  // Flush log every five seconds
  spdlog::flush_every(std::chrono::seconds(5));

  auto console_start = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
  // Start out with level=info. Config may change this
  console_start->set_level(spdlog::level::debug);
  console_start->set_pattern("[vscpl2drv-websocksrv: %c] [%^%l%$] %v");

  // Setting up logging defaults
  m_logLevel = spdlog::level::debug;

  m_bConsoleLogEnable = true;
  m_consoleLogPattern = "[vscpl2drv-websocksrv %c] [%^%l%$] %v";

  m_bEnableFileLog   = true;
  m_fileLogPattern   = "[vscpl2drv-websocksrv %c] [%^%l%$] %v";
  m_path_to_log_file = "/tmp/vscpl2drv-websocksrv.log";
  m_max_log_size     = 5242880;
  m_max_log_files    = 7;

  ////////////////////////////////////////////////////////
  //      Log files are configured in doLoadConfig      //
  ////////////////////////////////////////////////////////

  // Set default values
  m_url      = "ws://localhost:8884";
  m_web_root = ".";
#ifdef WIN32
  m_tls_ca_path          = "";
  m_tls_certificate_path = "c:/vscp/certs/cert.pem";
  m_tls_private_key_path = "c:/vscp/certs/key.pem";
#else
  m_tls_ca_path          = "";
  m_tls_certificate_path = "/etc/vscp/certs/cert.pem";
  m_tls_private_key_path = "/etc/vscp/certs/key.pem";
#endif

  m_maxClients    = 100;  // Max clients
  m_bEnableWS1    = true; // Enable ws1
  m_url_ws1       = "/ws1";
  m_bEnableWS2    = true; // Enable ws2
  m_url_ws2       = "/ws2";
  m_bEnableREST   = true; // Enable REST
  m_url_rest      = "/rest";
  m_bEnableStatic = true; // Enable static web pages

  m_mgr = {}; // Initialize mongoose event manager

  // Mongoose just log errors (config mongoose-debug)
  mg_log_set(MG_LL_ERROR);
}

////////////////////////////////////////////////////////////////////////////////
// Destructor
//

CWebSockSrv::~CWebSockSrv(void)
{
  close();

#ifdef WIN32
  CloseHandle(m_semSendQueue);
  CloseHandle(m_semReceiveQueue);
#else
  sem_destroy(&m_semSendQueue);
  sem_destroy(&m_semReceiveQueue);
#endif

  pthread_mutex_destroy(&m_mutexSendQueue);
  pthread_mutex_destroy(&m_mutexReceiveQueue);

  pthread_mutex_destroy(&m_mutex_UserList);

#ifdef WIN32
  // Cleanup Windows sockets
  WSACleanup();
#endif
}

////////////////////////////////////////////////////////////////////////////////
// open
//

int
CWebSockSrv::open(std::string &path, const uint8_t *pguid)
{
  int rv;

  // Must have a valid GUID
  if (NULL == pguid) {
    return false;
  }

  // Set GUID
  m_guid.getFromArray(pguid);

  // Save path for config file
  m_path = path;

  // Read configuration file
  if (VSCP_ERROR_SUCCESS != (rv = doLoadConfig(path))) {
    spdlog::error("[Websocket Server] Failed to load configuration file.");
    return rv;
  }

  // Start the server
  if (VSCP_ERROR_SUCCESS != start()) {
    spdlog::critical("Failed to start server.");
    spdlog::drop_all();
    return VSCP_ERROR_INIT_FAIL;
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
  // Do nothing if already terminated
  if (m_bQuit) {
    spdlog::drop_all();
    return VSCP_ERROR_SUCCESS;
  }

  m_bQuit = true; // terminate the thread
#ifndef WIN32
  sleep(1); // Give the thread some time to terminate
#else
  Sleep(1000);
#endif

  spdlog::drop_all();
  spdlog::shutdown();

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// doLoadConfig
//

int
CWebSockSrv::doLoadConfig(std::string &path)
{
  // Take away possible whitespace
  vscp_trim(path);

  // If first character of path is "{" expand it to home directory
  // we expect path to be a JSON string for us to parse
  if ('{' == path.at(0)) {
    spdlog::info("Configuration appears to be a JSON string.");
    try {
      m_j_config = json::parse(path);
    }
    catch (json::parse_error) {
      spdlog::critical("Failed to parse JSON configuration.");
      return VSCP_ERROR_PARSING;
    }
    catch (std::exception &e) {
      spdlog::critical("Failed to parse configuration. Exception='{}'", e.what());
      return VSCP_ERROR_PARSING;
    }
    catch (...) {
      spdlog::critical("Failed to parse configuration due to unknown error.");
      return VSCP_ERROR_PARSING;
    }
  }
  // If path is a file read it
  else if (vscp_fileExists(path)) {
    spdlog::info("Configuration appears to be a file.");
    try {
      std::ifstream in(path, std::ifstream::in);
      in >> m_j_config;
    }
    catch (json::parse_error) {
      spdlog::critical("Failed to parse JSON configuration.");
      return VSCP_ERROR_PARSING;
    }
    catch (std::exception &e) {
      spdlog::critical("Failed to parse configuration. Exception='{}'", e.what());
      return VSCP_ERROR_PARSING;
    }
    catch (...) {
      spdlog::critical("Failed to parse configuration due to unknown error.");
      return VSCP_ERROR_PARSING;
    }
  }
  else {
    // Configuration file does not exist
    return VSCP_ERROR_PARAMETER;
  }

  // Enable extra debug output
  if (m_j_config.contains("debug")) {
    try {
      m_bDebug = (m_j_config["debug"].get<bool>());
    }
    catch (const std::exception &ex) {
      spdlog::error("Failed to read 'debug' Error='{0}'", ex.what());
    }
    catch (...) {
      spdlog::error("Failed to read 'debug' due to unknown error.");
    }
  }
  else {
    spdlog::error("ReadConfig: Failed to read 'debug' Defaults will be used.");
  }

  // write
  if (m_j_config.contains("write")) {
    try {
      m_bWriteEnable = m_j_config["write"].get<bool>();
    }
    catch (const std::exception &ex) {
      spdlog::error("Failed to read 'write' Error='{0}'", ex.what());
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

  // interface m_url
  if (m_j_config.contains("interface") && m_j_config["interface"].is_string()) {
    m_url = m_j_config["interface"].get<std::string>();
  }
  else {
    spdlog::error("ReadConfig: Failed to read 'interface' Defaults ({0}) will be used.", m_url);
  }

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

  // Receive filter
  if (m_j_config.contains("rx-filter")) {
    try {
      std::string filter = m_j_config["rx-filter"].get<std::string>();
      if (!vscp_readFilterFromString(&m_rxfilter, filter.c_str())) {
        spdlog::error("ReadConfig: Failed to parse 'rx-filter' filter='{}'", filter);
      }
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'rx-filter' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'rx-filter' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'rx-filter' Defaults will be used.");
  }

  // max client queue size
  if (m_j_config.contains("max-client-queue-size")) {
    try {
      m_maxClientQueueSize = m_j_config["max-client-queue-size"].get<uint32_t>();
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'max-client-queue-size' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'max-client-queue-size' due to unknown error.");
    }
  }

  if (m_j_config.contains("url-ws1")) {
    try {
      m_url_ws1 = m_j_config["url-ws1"].get<std::string>();
      vscp_trim(m_url_ws1);
      // Verify that first character is "/"
      if (m_url_ws1.front() != '/') {
        m_url_ws1 = "/" + m_url_ws1;
      }
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'url-ws1' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'url-ws1' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'url-ws1' Defaults will be used.");
  }

  if (m_j_config.contains("url-ws2")) {
    try {
      m_url_ws2 = m_j_config["url-ws2"].get<std::string>();
      vscp_trim(m_url_ws2);
      // Verify that first character is "/"
      if (m_url_ws2.front() != '/') {
        m_url_ws2 = "/" + m_url_ws2;
      }
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'url-ws2' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'url-ws2' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'url-ws2' Defaults will be used.");
  }

  if (m_j_config.contains("url-rest")) {
    try {
      m_url_rest = m_j_config["url-rest"].get<std::string>();
      vscp_trim(m_url_rest);
      // Verify that first character is "/"
      if (m_url_rest.front() != '/') {
        m_url_rest = "/" + m_url_rest;
      }
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'url-rest' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'url-rest' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'url-rest' Defaults will be used.");
  }

  if (m_j_config.contains("web-root")) {
    try {
      m_web_root = m_j_config["web-root"].get<std::string>();
      vscp_trim(m_web_root);
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'web-root' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'web-root' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'web-root' Defaults will be used.");
  }

  // Root directory must not contain double dots. Make it absolute
  // Do the conversion only if the root dir spec does not contain overrides
  // char ppath[MG_PATH_MAX];
  // if (strchr(m_web_root.c_str(), ',') == NULL) {
  //   realpath(m_web_root.c_str(), ppath);
  //   m_web_root = ppath;
  // }

  MG_INFO(("Mongoose version : v%s", MG_VERSION));
  MG_INFO(("Listening on     : %s", m_interface.c_str()));
  MG_INFO(("Web root         : %s", m_web_root.c_str()));

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

  // Max number of clients 0 == unlimited
  if (m_j_config.contains("max-clients")) {
    try {
      m_maxClients = m_j_config["max-clients"].get<uint16_t>();
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'max-clients' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'max-clients' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'max-clients' Defaults will be used.");
  }

  // Enable ws1
  if (m_j_config.contains("enable-ws1")) {
    try {
      m_bEnableWS1 = m_j_config["enable-ws1"].get<bool>();
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'enable-ws1' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'enable-ws1' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'enable-ws1' Defaults will be used.");
  }

  // Enable ws2
  if (m_j_config.contains("enable-ws2")) {
    try {
      m_bEnableWS2 = m_j_config["enable-ws2"].get<bool>();
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'enable-ws2' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'enable-ws2' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'enable-ws2' Defaults will be used.");
  }

  // Enable REST
  if (m_j_config.contains("enable-rest")) {
    try {
      m_bEnableREST = m_j_config["enable-rest"].get<bool>();
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'enable-rest' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'enable-rest' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'enable-rest' Defaults will be used.");
  }

  // Enable static web
  if (m_j_config.contains("enable-static")) {
    try {
      m_bEnableStatic = m_j_config["enable-static"].get<bool>();
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig: Failed to read 'enable-static' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig: Failed to read 'enable-static' due to unknown error.");
    }
  }
  else {
    spdlog::warn("ReadConfig: Failed to read 'enable-static' Defaults will be used.");
  }

  ///////////////////////////////////////////////////////////////////////////
  //                          TLS / SSL
  ///////////////////////////////////////////////////////////////////////////

  if (m_j_config.contains("tls") && m_j_config["tls"].is_object()) {

    json j = m_j_config["tls"];

    // Certificate
    if (j.contains("certificate")) {
      try {
        m_tls_certificate_path = j["certificate"].get<std::string>();
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

    // private key
    if (j.contains("key")) {
      try {
        m_tls_private_key_path = j["key"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig:Failed to read 'key' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'key' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read 'key' Defaults will be used.");
    }
  }

  //  mongoose debugging
  if (m_j_config.contains("mongoose-debug")) {
    try {
      bool bMongooseDebug = m_j_config["mongoose-debug"].get<bool>();
      // mongoose.set("debug", bMongooseDebug);
      if (bMongooseDebug) {
        mg_log_set(MG_LL_DEBUG);
      }
      else {
        mg_log_set(MG_LL_ERROR);
      }
    }
    catch (const std::exception &ex) {
      spdlog::error("ReadConfig:Failed to read 'mongoose-debug' Error='{}'", ex.what());
    }
    catch (...) {
      spdlog::error("ReadConfig:Failed to read 'mongoose-debug' due to unknown error.");
    }
  }
  else {
    spdlog::debug("ReadConfig: Failed to read 'mongoose-debug' "
                  "Defaults will be used.");
  }

  ///////////////////////////////////////////////////////////////////////////
  //                          logging
  ///////////////////////////////////////////////////////////////////////////

  if (m_j_config.contains("logging") && m_j_config["logging"].is_object()) {

    json j = m_j_config["logging"];

    // Logging: log-level for both console and file
    if (j.contains("log-level")) {
      std::string str;
      try {
        str = j["log-level"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("[vscpl2drv-websocksrv]Failed to read 'log-level' Error='{0}'", ex.what());
      }
      catch (...) {
        spdlog::error("[vscpl2drv-websocksrv]Failed to read 'log-level' due to unknown error.");
      }
      vscp_makeLower(str);
      if (std::string::npos != str.find("off")) {
        m_logLevel = spdlog::level::off;
      }
      else if (std::string::npos != str.find("critical")) {
        m_logLevel = spdlog::level::critical;
      }
      else if (std::string::npos != str.find("err")) {
        m_logLevel = spdlog::level::err;
      }
      else if (std::string::npos != str.find("warn")) {
        m_logLevel = spdlog::level::warn;
      }
      else if (std::string::npos != str.find("info")) {
        m_logLevel = spdlog::level::info;
      }
      else if (std::string::npos != str.find("debug")) {
        m_logLevel = spdlog::level::debug;
      }
      else if (std::string::npos != str.find("trace")) {
        m_logLevel = spdlog::level::trace;
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

    // Logging: file-logging-enable
    if (j.contains("file-enable-log")) {
      try {
        m_bEnableFileLog = j["file-enable-log"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig:Failed to read 'file-enable-log' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'file-enable-log' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read LOGGING 'file-enable-log' "
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

    // * * * CONSOLE LOGGING * * *

    // Logging: console-logging-enable
    if (j.contains("console-enable-log")) {
      try {
        m_bConsoleLogEnable = j["console-enable-log"].get<bool>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig:Failed to read 'console-enable-log' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'console-enable-log' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read LOGGING 'console-enable-log' "
                    "Defaults will be used.");
    }

    // Logging: console-pattern
    if (j.contains("console-pattern")) {
      try {
        m_consoleLogPattern = j["console-pattern"].get<std::string>();
      }
      catch (const std::exception &ex) {
        spdlog::error("ReadConfig:Failed to read 'console-pattern' Error='{}'", ex.what());
      }
      catch (...) {
        spdlog::error("ReadConfig:Failed to read 'console-pattern' due to unknown error.");
      }
    }
    else {
      spdlog::debug("ReadConfig: Failed to read LOGGING 'console-pattern' "
                    "Defaults will be used.");
    }

  } // Logging
  else {
    spdlog::info("ReadConfig: No logging has been setup.");
  }

  ///////////////////////////////////////////////////////////////////////////
  //                          Setup logger
  ///////////////////////////////////////////////////////////////////////////

  // Console log
  auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

  if (m_bConsoleLogEnable) {
    console_sink->set_level(m_logLevel);
    console_sink->set_pattern(m_consoleLogPattern);
  }
  else {
    // If disabled set to off
    console_sink->set_level(spdlog::level::off);
  }

  auto rotating_file_sink =
    std::make_shared<spdlog::sinks::rotating_file_sink_mt>(m_path_to_log_file.c_str(), m_max_log_size, m_max_log_files);

  if (m_bEnableFileLog) {
    rotating_file_sink->set_level(m_logLevel);
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
  spdlog::register_logger(logger);
  spdlog::set_default_logger(logger);

  logger->set_level(m_logLevel);

  spdlog::debug("Logger initialized.");

  // ------------------------------------------------------------------------

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

  spdlog::debug("Read configuration");

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
  spdlog::debug("Controlobject: Starting WebSocket interface...");

  m_bQuit = false;

#ifdef WIN32
  m_websockWorkerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) websockWorkerThread, this, 0, NULL);
  if (m_websockWorkerThread == NULL) {
    spdlog::error("Controlobject: Unable to start the websocket worker thread.");
    return VSCP_ERROR_ERROR;
  }
#else
  if (pthread_create(&m_websockWorkerThread, NULL, websockWorkerThread, this)) {
    spdlog::error("Controlobject: Unable to start the websocket worker thread.");
    return VSCP_ERROR_ERROR;
  }
#endif

  return VSCP_ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// stop
//

int
CWebSockSrv::stop(void)
{
  // Tell the thread it's time to quit
  m_bQuit = true;

  spdlog::debug("Controlobject: Terminating WebSocket thread.");

// Wait for thread to finish and clean up
#ifdef WIN32
  if (m_websockWorkerThread == NULL) { // Check if thread was created
    // Not started
    return VSCP_ERROR_SUCCESS;
  }
  CloseHandle(m_websockWorkerThread);
  m_websockWorkerThread = NULL; // Reset thread handle
#else
  if (!m_websockWorkerThread) { // Check if thread was created
    // Not started
    return VSCP_ERROR_SUCCESS;
  }
  pthread_join(m_websockWorkerThread, NULL);
  m_websockWorkerThread = 0; // Reset thread ID
#endif

  spdlog::debug("Controlobject: Terminated WebSocket thread.");

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// restart
//

int
CWebSockSrv::restart(void)
{
  if (!stop()) {
    spdlog::warn("Failed to stop VSCP websocket server.");
  }

  if (!start()) {
    spdlog::warn("Failed to start VSCP websocket server.");
  }

  return VSCP_ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////
// addEvent2SendQueue
//
//  Send event to host
//

int
CWebSockSrv::addEvent2SendQueue(const vscpEvent *pEvent)
{
  pthread_mutex_lock(&m_mutexSendQueue);
  if (!m_maxClientQueueSize && (m_sendQueue.size() >= m_maxClientQueueSize)) {
    pthread_mutex_unlock(&m_mutexSendQueue);
    spdlog::warn("Send queue full, dropping event.");
    return VSCP_ERROR_FIFO_FULL;
  }
  m_sendQueue.push_back((vscpEvent *) pEvent);
#ifdef WIN32
  ReleaseSemaphore(m_semSendQueue, 1, NULL);
#else
  sem_post(&m_semSendQueue);
#endif
  pthread_mutex_unlock(&m_mutexSendQueue);
  return VSCP_ERROR_SUCCESS;
}

//////////////////////////////////////////////////////////////////////
// addEvent2ReceiveQueue
//
//  Send event to host
//

int
CWebSockSrv::addEvent2ReceiveQueue(const vscpEvent *pEvent)
{
  pthread_mutex_lock(&m_mutexReceiveQueue);
  m_receiveQueue.push_back((vscpEvent *) pEvent);
  pthread_mutex_unlock(&m_mutexReceiveQueue);
#ifdef WIN32
  ReleaseSemaphore(m_semReceiveQueue, 1, NULL);
#else
  sem_post(&m_semReceiveQueue);
#endif
  return VSCP_ERROR_SUCCESS;
}

//////////////////////////////////////////////////////////////////////
// addEvent2ReceiveQueue
//

int
CWebSockSrv::addEvent2ReceiveQueue(vscpEventEx &ex)
{
  vscpEvent *pev = new vscpEvent();
  if (!vscp_convertEventExToEvent(pev, &ex)) {
    spdlog::error("Failed to convert event from ex to ev.");
    vscp_deleteEvent(pev);
    return false;
  }

  if (NULL == pev) {
    spdlog::error("addEvent2ReceiveQueue - Unable to allocate event storage.");
    return false;
  }

  if (vscp_doLevel2Filter(pev, &m_rxfilter)) {
    pthread_mutex_lock(&m_mutexReceiveQueue);
    m_receiveQueue.push_back(pev);
    pthread_mutex_unlock(&m_mutexReceiveQueue);
#ifdef WIN32
    ReleaseSemaphore(m_semReceiveQueue, 1, NULL);
#else
    sem_post(&m_semReceiveQueue);
#endif
  }
  else {
    vscp_deleteEvent(pev);
  }
  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventToClient
//

int
CWebSockSrv::sendEventToClient(CWebSockSession *pSessionItem, const vscpEvent *pEvent)
{
  // Must be valid pointers
  if (NULL == pSessionItem) {
    spdlog::error("sendEventToClient - Pointer to session item is null");
    return VSCP_ERROR_INVALID_POINTER;
  }

  if (NULL == pEvent) {
    spdlog::error("sendEventToClient - Pointer to event is null");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must be connected
  if ((pSessionItem->getConnection() == NULL)) {
    return VSCP_ERROR_NOT_CONNECTED;
  }

  // Client channel must be open for it to receive events
  if (!pSessionItem->isOpen()) {
    // Save event in the session send queue
    return pSessionItem->addToInputQueue(pEvent);
  }

  // Must be authenticated
  if (pSessionItem->getConnState() < WEBSOCK_CONN_STATE_AUTHENTICATED) {
    return VSCP_ERROR_INVALID_PERMISSION;
  }

  // User must be authorised to receive events
  if (!(pSessionItem->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
    return VSCP_ERROR_INVALID_PERMISSION;
  }

  // Check if filtered out - if so do nothing here
  if (!vscp_doLevel2Filter(pEvent, pSessionItem->getFilter())) {
    if (m_j_config.contains("debug") && m_j_config["debug"].get<bool>()) {
      spdlog::debug("sendEventToClient - Filtered out");
    }
    return VSCP_ERROR_NOT_SUPPORTED;
  }

  spdlog::debug("Sending event to client {}", pSessionItem->getConnection()->id);

  // Write it out
  if (WS_TYPE_1 == pSessionItem->getWsType()) {
    std::string str;
    if (vscp_convertEventToString(str, pEvent)) {
      spdlog::debug("Received ws event {}", str.c_str());
      str = ("E;") + str;
      mg_ws_send(pSessionItem->getConnection(), (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    }
  }
  else if (WS_TYPE_2 == pSessionItem->getWsType()) {
    std::string strEvent;
    vscp_convertEventToJSON(strEvent, pEvent);
    spdlog::debug("Received ws event {}", strEvent.c_str());
    std::string str = vscp_str_format(WS2_EVENT, strEvent.c_str());
    mg_ws_send(pSessionItem->getConnection(), (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// sendEventAllClients
//

int
CWebSockSrv::sendEventAllClients(const vscpEvent *pEvent)
{

  if (NULL == pEvent) {
    spdlog::error("sendEventAllClients - No event to send");
    return false;
  }

  pthread_mutex_lock(&m_mutex_websocketSession);
  std::map<unsigned long, CWebSockSession *>::iterator it;
  for (it = m_websocketSessionMap.begin(); it != m_websocketSessionMap.end(); ++it) {
    CWebSockSession *pSessionItem = it->second;

    if (NULL != pSessionItem) {
      int rv;
      if (VSCP_ERROR_SUCCESS != (rv = sendEventToClient(pSessionItem, pEvent))) {
        if (VSCP_ERROR_NOT_OPEN == rv) {
          spdlog::debug("sendEventAllClients - Client channel not open - skipping");
        }
        else if (VSCP_ERROR_NOT_CONNECTED == rv) {
          spdlog::debug("sendEventAllClients - Client not connected - skipping");
        }
        else {
          spdlog::error("sendEventAllClients - Failed to send event {} to client {}",
                        rv,
                        pSessionItem->getConnection()->id);
        }
      }
    }
  } // for

  pthread_mutex_unlock(&m_mutex_websocketSession);
  mg_wakeup(&m_mgr, 0, nullptr, 0);

  return VSCP_ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// sendQueueEventsToClient
//

int
CWebSockSrv::sendQueueEventsToClient(CWebSockSession *pSession)
{
  // Check pointer
  if (NULL == pSession) {
    spdlog::error("sendQueueEventsToClient - Pointer to session item is null");
    return VSCP_ERROR_INVALID_POINTER;
  }

  // Must be connected
  if (pSession->getConnection() == NULL) {
    return VSCP_ERROR_NOT_CONNECTED;
  }

  // Client channel must be open for it to receive events
  if (!pSession->isOpen()) {
    return VSCP_ERROR_NOT_OPEN;
  }

  // Send all queued events to the client
  while (pSession->m_inputQueue.size()) {

    vscpEvent *pEvent;
    pthread_mutex_lock(&pSession->m_mutexInputQueue);
    pEvent = pSession->m_inputQueue.front();
    pSession->m_inputQueue.pop_front();
    pthread_mutex_unlock(&pSession->m_mutexInputQueue);
    if (NULL != pEvent) {

      int rv;
      if (VSCP_ERROR_SUCCESS != (rv = sendEventToClient((CWebSockSession *) pSession, pEvent))) {
        spdlog::error("sendQueueEventsToClient - Failed to send queued event {} to client {}",
                      rv,
                      pSession->getConnection()->id);
      }

      // Remove the event
      vscp_deleteEvent_v2(&pEvent);

    } // Valid pEvent pointer

  } // while events in queue

  return VSCP_ERROR_SUCCESS;
}

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
//     spdlog::error( "Internal error: sendEvent - conn == NULL");
//     return false;
//   }

//   CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
//  if (NULL == pSession) {
//     spdlog::error( "Internal error: sendEvent - pSession == NULL");
//     return false;
//   }

//   if (NULL == pev) {
//     spdlog::error( "Internal error: sendEvent - pEvent == NULL");
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
//     spdlog::error( "Internal error: sendEvent - conn == NULL");
//     return false;
//   }

//   CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
//  if (NULL == pSession) {
//     spdlog::error( "Internal error: sendEvent - pSession == NULL");
//     return false;
//   }

//   if (NULL == pex) {
//     spdlog::error( "Internal error: sendEvent - pEvent == NULL");
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

  std::map<unsigned long, CWebSockSession *>::iterator iter;
  for (iter = m_websocketSessionMap.begin(); iter != m_websocketSessionMap.end(); ++iter) {

    CWebSockSession *pSession = iter->second;
    if (NULL == pSession) {
      continue;
    }

    if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
      continue;
    }

    if (NULL == pSession->getConnection()) {
      continue;
    }

    if (pSession->isOpen() && pSession->m_inputQueue.size()) {

      vscpEvent *pEvent;
      pthread_mutex_lock(&pSession->m_mutexInputQueue);
      pEvent = pSession->m_inputQueue.front();
      pSession->m_inputQueue.pop_front();
      pthread_mutex_unlock(&pSession->m_mutexInputQueue);
      if (NULL != pEvent) {

        if ((pSession->getConnection() == NULL) && (1)) {
          vscp_deleteEvent_v2(&pEvent);
          continue;
        }

        // Run event through filter
        if (vscp_doLevel2Filter(pEvent, pSession->getFilter())) {

          // User must be authorised to receive events
          if (!(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
            continue;
          }

          // spdlog::debug("Received ws event {}", str.c_str());

          // Write it out
          if (WS_TYPE_1 == pSession->getWsType()) {
            std::string str;
            if (vscp_convertEventToString(str, pEvent)) {
              str = ("E;") + str;
              mg_ws_send(pSession->getConnection(), (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
            }
          }
          else if (WS_TYPE_2 == pSession->getWsType()) {
            std::string strEvent;
            vscp_convertEventToJSON(strEvent, pEvent);
            std::string str = vscp_str_format(WS2_EVENT, strEvent.c_str());
            mg_ws_send(pSession->getConnection(), (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
          }
        }

        // Remove the event
        vscp_deleteEvent_v2(&pEvent);

      } // Valid pEvent pointer

    } // events available

  } // for

  pthread_mutex_unlock(&m_mutex_websocketSession);
}

///////////////////////////////////////////////////////////////////////////////
// websock_authentication
//
// w1 client sends
//      "AUTH;iv;AES128("username:password) using main key
// w2 client sends
//      JSON equivalent

int
CWebSockSrv::authentication(struct mg_connection *conn, std::string &strContent, std::string &strIV)
{
  uint8_t buf[2048]; //, secret[2048];
  uint8_t iv[16];
  std::string strUser, strPassword;

  bool bValidHost = false;

  // Check pointers
  if ((NULL == conn)) {
    spdlog::error("[Websocket Client] Authentication: Invalid connection context pointer.");
    return false;
  }

  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) conn->fn_data;
  if (NULL == pWebSockSrv) {
    spdlog::error("websockWorkerThread: Invalid CWebSockSrv pointer.");
    return false;
  }

  CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
  if (NULL == pSession) {
    spdlog::error("[Websocket Client] Authentication: Invalid session pointer. ");
    return false;
  }

  if (0 == vscp_hexStr2ByteArray(iv, 16, (const char *) strIV.c_str())) {
    spdlog::error("[Websocket Client] Authentication: No room "
                  "for iv block. ");
    return false; // Not enough room in buffer
  }

  uint8_t content[16];
  if (0 == vscp_hexStr2ByteArray(content, 16, (const char *) strContent.c_str())) {
    spdlog::error("[Websocket Client] Authentication: No room "
                  "for content block. ");
    return false; // Not enough room in buffer
  }

  // Size should always be 16 bytes here - no padding required

  memset(buf, 0, sizeof(buf));
  AES_CBC_decrypt_buffer(AES128, buf, content, 16, m_encryptionKey, iv);

  std::string str = std::string((const char *) buf);
  std::deque<std::string> tokens;
  vscp_split(tokens, str, ":");

  if (tokens.size() < 2) {
    spdlog::error("[Websocket Client] Authentication: Malformed "
                  "authentication data from client. (Should be 'user:password') ");
    return false; // Not enough tokens
  }

  // Get username
  if (tokens.empty()) {
    spdlog::error("[Websocket Client] Authentication: Missing "
                  "username from client. ");
    return false; // No username
  }

  strUser = tokens.front();
  tokens.pop_front();
  vscp_trim(strUser);

  // Get password
  if (tokens.empty()) {
    spdlog::error("[Websocket Client] Authentication: Missing "
                  "password from client. ");
    return false; // No username
  }

  strPassword = tokens.front();
  tokens.pop_front();
  vscp_trim(strPassword);

  // Check if user is valid
  CUserItem *pUserItem = m_userList.getUser(strUser);
  if (NULL == pUserItem) {
    spdlog::error("[Websocket Client] Authentication: CUserItem "
                  "allocation problem ");
    return false;
  }

  char addrbuf[64];
  if (conn->rem.is_ip6) {
    mg_snprintf(addrbuf, sizeof(addrbuf), "%M", mg_print_ip6, "abcdefghijklmnop");
  }
  else {
    mg_snprintf(addrbuf, sizeof(addrbuf), "%M", mg_print_ip4, "abcd");
  }

  if (!pUserItem->validateUser(strPassword)) {
    spdlog::error("[Websocket Client] Authentication: User {0} at host "
                  "[{1}] gave wrong password.",
                  (const char *) strUser.c_str(),
                  addrbuf);
    return false;
  }

  // Check if remote ip is valid
  bValidHost = pUserItem->isAllowedToConnect(conn->rem.ip4);

  if (!bValidHost) {
    // Log valid login
    spdlog::error("[Websocket Client] Authentication: Host "
                  "[{0}] NOT allowed to connect.",
                  addrbuf);
    return false;
  }

  pSession->setAuthenticated(true);

  // Add user to client
  pSession->setUserItem(pUserItem);

  // Set user filter
  pSession->setFilter(pUserItem->getUserFilter());

  // Log valid login
  spdlog::info("[Websocket Client] Authentication: Host {0}"
               " User {1} allowed to connect.",
               addrbuf,
               (const char *) strUser.c_str());
  return true;
}

///////////////////////////////////////////////////////////////////////////////
// newSession
//

CWebSockSession *
CWebSockSrv::newSession(unsigned long id, const char *pws_version, const uint8_t *pkey)
{
  CWebSockSession *pSession = NULL;

  // Check pointers
  if (NULL == pws_version) {
    spdlog::error("[Websockets] New session: Invalid protocol version pointer.");
    return NULL;
  }

  if (NULL == pkey) {
    spdlog::error("[Websockets] New session: Invalid encryption key pointer.");
    return NULL;
  }

  // Check for maximum number of clients (0 = no limit)
  if (m_maxClients && (m_websocketSessionMap.size() > m_maxClients)) {
    spdlog::error("[Websockets] New session: Maximum number of clients reached.");
    return NULL;
  }

  // Create fresh session
  pSession = new CWebSockSession;
  if (NULL == pSession) {
    spdlog::error("[Websockets] New session: Unable to create session object.");
    return NULL;
  }

  // Init.
  pSession->setKey(getEncryptionKey());
  pSession->setConnState(WEBSOCK_CONN_STATE_CONNECTED);
  pSession->setVersion(atoi(pws_version)); // Store protocol version

  // Add the client to the Client List
  pthread_mutex_lock(&m_mutex_websocketSession);
  m_websocketSessionMap[id] = pSession;
  pthread_mutex_unlock(&m_mutex_websocketSession);

  return pSession;
}

///////////////////////////////////////////////////////////////////////////////
// removeSession
//

int
CWebSockSrv::removeSession(unsigned long id)
{
  // Find the session
  CWebSockSession *pSession = NULL;

  pthread_mutex_lock(&m_mutex_websocketSession);
  auto it = m_websocketSessionMap.find(id);
  if (it != m_websocketSessionMap.end()) {
    pSession = it->second;
    m_websocketSessionMap.erase(it);
  }
  pthread_mutex_unlock(&m_mutex_websocketSession);

  return VSCP_ERROR_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// getSession
//

CWebSockSession *
CWebSockSrv::getSession(unsigned long id)
{
  CWebSockSession *pSession = NULL;

  pthread_mutex_lock(&m_mutex_websocketSession);
  auto it = m_websocketSessionMap.find(id);
  if (it != m_websocketSessionMap.end()) {
    pSession = it->second;
  }
  pthread_mutex_unlock(&m_mutex_websocketSession);

  return pSession;
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
//   CWebSockSession *pSession = websock_new_session(conn);

//   if (NULL != pSession) {
//     reject = 0;
//   }

//   // This is a WS1 type connection
//   pSession->m_wstypes = WS_TYPE_1;

//   mg_unlock_context(ctx);

#ifdef __VSCP_DEBUG_WEBSOCKET
//     spdlog::error( "[Websocket ws1] WS1 Connection: client {}", (reject ? "rejected" : "accepted"));
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

void
CWebSockSrv::ws1_readyHandler(struct mg_connection *conn, void *cbdata)
{
  // Check pointers
  if (NULL == conn) {
    return;
  }

  // No session data available yet in the conn object
  // It will be set in the connect handler
  CWebSockSession *pSession = (CWebSockSession *) cbdata; // conn->pfn_data;
  if (NULL == pSession) {
    return;
  }

  // if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
  //   return;
  // }

  // Record activity
  pSession->setLastActiveTime(time(NULL));

  // Start authentication
  spdlog::debug("[Websocket ws1] Sending AUTH0 to client. +;AUTH0;{0}", pSession->getSid());
  std::string str = vscp_str_format(("+;AUTH0;%s"), pSession->getSid());
  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

  pSession->setConnState(WEBSOCK_CONN_STATE_DATA);
}

////////////////////////////////////////////////////////////////////////////////
// ws1_dataHandler
//

int
CWebSockSrv::ws1_dataHandler(struct mg_connection *conn, struct mg_ws_message *wm /*, void *cbdata*/)
{
  std::string strWsPkt;

  // Check pointers
  if (NULL == conn) {
    return VSCP_ERROR_ERROR;
  }

  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) conn->fn_data;
  if (NULL == pWebSockSrv) {
    spdlog::error("websockWorkerThread: Invalid CWebSockSrv pointer.");
    return VSCP_ERROR_ERROR;
  }

  CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
  if (NULL == pSession) {
    return VSCP_ERROR_ERROR;
  }

  if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
    return VSCP_ERROR_ERROR;
  }

  // Record activity
  pSession->setLastActiveTime(time(NULL));

  switch (wm->flags & 0x0F) {

    case WEBSOCKET_OP_CONTINUE:

      spdlog::debug("Websocket WS1 - opcode = Continuation");

      // Save and concatenate message parts
      pSession->addConcatenatedString(wm->data);
      break;

      // https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
    case WEBSOCKET_OP_TEXT:
      spdlog::debug("Websocket WS1 - opcode = text[{}]", strWsPkt.c_str());
      if (wm->flags & WEBSOCKET_OP_FINAL) {
        // Last part of message - get all parts
        pSession->addConcatenatedString(wm->data);
        strWsPkt = pSession->getConcatenatedString();
        pSession->clearConcatenatedString();
      }
      else {
        // Not last part - just add to existing parts
        pSession->addConcatenatedString(wm->data);
        return VSCP_ERROR_SUCCESS;
      }

      spdlog::debug("Websocket WS1 - Full message received: {}", strWsPkt.c_str());

      if (!ws1_message(conn, strWsPkt)) {
        return VSCP_ERROR_ERROR;
      }
      break;

    case WEBSOCKET_OP_BINARY:
      spdlog::debug("Websocket WS1 - opcode = BINARY");
      break;

    case WEBSOCKET_OP_CLOSE:
      spdlog::debug("Websocket WS1 - opcode = Connection close");
      break;

    case WEBSOCKET_OP_PING:
      spdlog::debug("Websocket WS1 - opcode = Ping");
      mg_ws_send(conn, NULL, 0, WEBSOCKET_OP_PONG);
      break;

    case WEBSOCKET_OP_PONG:
      spdlog::debug("Websocket WS2 - Pong received/Pong sent,");
      mg_ws_send(conn, NULL, 0, WEBSOCKET_OP_PING);
      break;

    default:
      break;
  }

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

  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) conn->fn_data;
  if (NULL == pWebSockSrv) {
    spdlog::error("websockWorkerThread: Invalid CWebSockSrv pointer.");
    return false;
  }

  CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
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
        spdlog::error("ws1: Exception occurred ws1_command");
        str = vscp_str_format(("-;C;%d;%s"), (int) WEBSOCK_ERROR_GENERAL, WEBSOCK_STR_ERROR_GENERAL);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      }
      break;

    // Event | 'E' ; head(byte) , vscp_class(unsigned short) ,
    // vscp_type(unsigned
    //              short) , GUID(16*byte), data(0-487 bytes) |
    case 'E': {

      // Must be authorised to do this
      if (!pSession->isAuthenticated()) {

        str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORISED, WEBSOCK_STR_ERROR_NOT_AUTHORISED);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        spdlog::error("[Websocket ws1] User {0} is not "
                      "authorised.\n",
                      pSession->getUserItem()->getUserName().c_str());

        return true;
      }

      // User must be allowed to send events
      if (!(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

        str = vscp_str_format(("-;%d;%s"),
                              (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                              WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);

        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        spdlog::error("[Websocket ws1] User {0} is not "
                      "allowed to send events.\n",
                      pSession->getUserItem()->getUserName().c_str());

        return true; // We still leave channel open
      }

      // Point beyond initial info "E;"
      strWsPkt = vscp_str_right(strWsPkt, strWsPkt.length() - 2);
      vscpEventEx ex;

      if (vscp_convertStringToEventEx(&ex, strWsPkt)) {

        // If GUID is all null give it GUID of interface
        if (vscp_isGUIDEmpty(ex.GUID)) {
          pSession->getGuid()->writeGUID(ex.GUID);
        }

        // Is this user allowed to send events
        if (!(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

          str = vscp_str_format(("-;%d;%s"),
                                (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);

          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          spdlog::error("[Websocket ws1] User {0} is not "
                        "allowed to send events.\n",
                        pSession->getUserItem()->getUserName().c_str());

          return true; // We still leave channel open
        }

        // Is user allowed to send CLASS1.PROTOCOL events
        if ((VSCP_CLASS1_PROTOCOL == ex.vscp_class) && (VSCP_CLASS2_LEVEL1_PROTOCOL == ex.vscp_class) &&
            !(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT)) {

          str = vscp_str_format(("-;%d;%s"),
                                (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          spdlog::error("[Websocket ws1] User {0} is not "
                        "authorised to send CLASS1.PROTOCOL events.\n",
                        pSession->getUserItem()->getUserName().c_str());

          return true;
        }

        // Is user allowed to send CLASS2.PROTOCOL events
        if ((VSCP_CLASS2_PROTOCOL == ex.vscp_class) &&
            !(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT)) {

          str = vscp_str_format(("-;%d;%s"),
                                (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          spdlog::error("[Websocket ws1] User {0} is not "
                        "authorised to send CLASS2.PROTOCOL events.\n",
                        pSession->getUserItem()->getUserName().c_str());

          return true;
        }

        // Is user allowed to send CLASS2.HLO events
        if ((VSCP_CLASS2_HLO == ex.vscp_class) &&
            !(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT)) {

          str = vscp_str_format(("-;%d;%s"),
                                (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          spdlog::error("[Websocket ws1] User {0} is not "
                        "authorised to send CLASS2.HLO events.\n",
                        pSession->getUserItem()->getUserName().c_str());

          return true;
        }

        // Check if this user is allowed to send this event
        if (!pSession->getUserItem()->isUserAllowedToSendEvent(ex.vscp_class, ex.vscp_type)) {

          str = vscp_str_format(("-;%d;%s"),
                                (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT,
                                WEBSOCK_ERROR_NOT_ALLOWED_TO_SEND_EVENT);

          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          spdlog::error("[websocket ws1] User {0} is not allowed to "
                        "send event class={1} type={2}.",
                        pSession->getUserItem()->getUserName().c_str(),
                        ex.vscp_class,
                        ex.vscp_type);

          return true; // Keep connection open
        }

        ex.obid = conn->id; // Set the obid
        if (VSCP_ERROR_SUCCESS == addEvent2ReceiveQueue(ex)) {
          mg_ws_send(conn, (const char *) "+;EVENT", 7, WEBSOCKET_OP_TEXT);
          spdlog::debug("[websocket ws1] Received ws1 event {0} from client {1}",
                        strWsPkt.c_str(),
                        pSession->getConnection()->id);
        }
        else {
          str = vscp_str_format(("-;%d;%s"), (int) WEBSOCK_ERROR_TX_BUFFER_FULL, WEBSOCK_STR_ERROR_TX_BUFFER_FULL);
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
        }

        // Send event to all other clients
        for (struct mg_connection *wc = conn->mgr->conns; wc != NULL; wc = wc->next) {

          if (wc == conn) {
            continue; // Don't send it back to the sender
          }

          if (NULL == wc->pfn_data) {
            // Write it out
            if (WS_TYPE_1 == pSession->getWsType()) {
              std::string str;
              if (vscp_convertEventExToString(str, &ex)) {
                str = ("E;") + str;
                mg_ws_send(wc, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
              }
            }
          }
        }
      }
    } // 'E'
    break;

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

  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) conn->fn_data;
  if (NULL == pWebSockSrv) {
    spdlog::error("websockWorkerThread: Invalid CWebSockSrv pointer.");
    return VSCP_ERROR_ERROR;
  }

  CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
  if (NULL == pSession) {
    return VSCP_ERROR_ERROR;
  }

#ifdef __VSCP_DEBUG_WEBSOCKET
  spdlog::error("[Websocket ws1] Command = {0}", strCmd.c_str());
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

  spdlog::debug("[Websocket ws1] Command token = {0}", strTok.c_str());

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
    if (pSession->isAuthenticated()) {

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

    // Must have sid and encrypted "user:password"
    if (tokens.size() < 2) {
      spdlog::error("WS1: AUTH failed (syntax)");
      str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      return VSCP_ERROR_SUCCESS; // We still leave channel open
    }

    try {
      std::string str;
      std::string strUser;

      std::string strIV = tokens.front();
      tokens.pop_front();

      // IV should be 32 characters long
      if (strIV.length() != 32) {
        spdlog::error("WS1: AUTH failed (invalid length of iv)");
        str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
        return VSCP_ERROR_SUCCESS; // We still leave channel open
      }

      // Make uppercase
      std::transform(strIV.begin(), strIV.end(), strIV.begin(), ::toupper);

      // iv should be the same as sid
      if (strIV != pSession->getSid()) {
        spdlog::error("WS1: AUTH failed (invalid iv)");
        str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
        return VSCP_ERROR_SUCCESS; // We still leave channel open
      }

      std::string strCrypto = tokens.front();
      tokens.pop_front();

      // Should be 32 characters long
      if (strCrypto.length() != 32) {
        spdlog::error("WS1: AUTH failed (invalid length of crypto)");
        str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
        return VSCP_ERROR_SUCCESS; // We still leave channel open
      }

      // Make uppercase
      std::transform(strCrypto.begin(), strCrypto.end(), strCrypto.begin(), ::toupper);

      if (authentication(conn, strCrypto, strIV)) {
        std::string userSettings;
        pSession->getUserItem()->getAsString(userSettings);
        str = vscp_str_format(("+;AUTH1;%s"), (const char *) userSettings.c_str());
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      }
      else {
        str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORISED, WEBSOCK_STR_ERROR_NOT_AUTHORISED);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
        pSession->generateSid();           // Generate new sid
        pSession->setAuthenticated(false); // not authenticated
      }
    }
    catch (...) {
      spdlog::error("WS1: AUTH failed (syntax)");
      str = vscp_str_format(("-;AUTH;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    }
  }

  // ------------------------------------------------------------------------
  //                                OPEN
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "OPEN")) {

    // Must be authorised to do this
    if (!pSession->isAuthenticated()) {
      str = vscp_str_format(("-;OPEN;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORISED, WEBSOCK_STR_ERROR_NOT_AUTHORISED);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      return VSCP_ERROR_SUCCESS; // We still leave channel open
    }

    pSession->setOpen(true);
    pSession->setConnection(conn);
    mg_ws_send(conn, (const char *) "+;OPEN", 6, WEBSOCKET_OP_TEXT);

    // Send any events that may be in the queue
    sendQueueEventsToClient(pSession);
  }

  // ------------------------------------------------------------------------
  //                                CLOSE
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "CLOSE")) {
    pSession->setOpen(false);
    mg_ws_send(conn, (const char *) "+;CLOSE", 7, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                             SETFILTER/SF
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "SETFILTER") || vscp_startsWith(strTok, "SF")) {

    unsigned char ifGUID[16];
    memset(ifGUID, 0, 16);

    // Must be authorised to do this
    if (!pSession->isAuthenticated()) {

      str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORISED, WEBSOCK_STR_ERROR_NOT_AUTHORISED);

      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      spdlog::error("[Websocket ws1] User/host not authorised to set a filter.");

      return VSCP_ERROR_SUCCESS; // We still leave channel open
    }

    // Check privilege
    if (!(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_SETFILTER)) {

      str = vscp_str_format(("-;SF;%d;%s"),
                            (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                            WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);

      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      spdlog::error("[Websocket ws1] User [{0}] not "
                    "allowed to set a filter.\n",
                    pSession->getUserItem()->getUserName().c_str());
      return VSCP_ERROR_SUCCESS; // We still leave channel open
    }

    // Get filter
    if (!tokens.empty()) {

      strTok = tokens.front();
      tokens.pop_front();

      pthread_mutex_lock(&pSession->m_mutexInputQueue);
      if (!vscp_readFilterFromString(pSession->getFilter(), strTok)) {

        str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);

        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        pthread_mutex_unlock(&pSession->m_mutexInputQueue);
        return VSCP_ERROR_SUCCESS;
      }

      pthread_mutex_unlock(&pSession->m_mutexInputQueue);
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

      pthread_mutex_lock(&pSession->m_mutexInputQueue);
      if (!vscp_readMaskFromString(pSession->getFilter(), strTok)) {

        str = vscp_str_format(("-;SF;%d;%s"), (int) WEBSOCK_ERROR_SYNTAX_ERROR, WEBSOCK_STR_ERROR_SYNTAX_ERROR);

        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        pthread_mutex_unlock(&pSession->m_mutexInputQueue);
        return VSCP_ERROR_SUCCESS;
      }

      pthread_mutex_unlock(&pSession->m_mutexInputQueue);
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

    // Must be authorised to do this
    if (!pSession->isAuthenticated()) {

      str = vscp_str_format(("-;CLRQ;%d;%s"), (int) WEBSOCK_ERROR_NOT_AUTHORISED, WEBSOCK_STR_ERROR_NOT_AUTHORISED);

      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      spdlog::error("[Websocket ws1] User/host not authorised to clear the queue.");

      return VSCP_ERROR_SUCCESS; // We still leave channel open
    }

    std::deque<vscpEvent *>::iterator it;
    pthread_mutex_lock(&pSession->m_mutexInputQueue);

    for (it = pSession->m_inputQueue.begin(); it != pSession->m_inputQueue.end(); ++it) {
      vscpEvent *pEvent = *it;
      pSession->m_inputQueue.pop_front();
      vscp_deleteEvent_v2(&pEvent);
    }

    pSession->m_inputQueue.clear();
    pthread_mutex_unlock(&pSession->m_mutexInputQueue);

    mg_ws_send(conn, (const char *) "+;CLRQ", 6, WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                              VERSION
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "VERSION")) {

    std::string strvalue;

    std::string strResult = ("+;VERSION;");
    strResult += VSCPL2DRV_WEBSOCKSRV_DISPLAY_VERSION;
    strResult += (";");
    strResult += vscp_str_format(("%d.%d.%d.%d"),
                                 VSCP_WS1_PROTOCOL_VERSION,
                                 VSCP_WS1_PROTOCOL_MINOR_VERSION,
                                 VSCP_WS1_PROTOCOL_RELEASE_VERSION,
                                 VSCP_WS1_PROTOCOL_BUILD_VERSION);
    // Positive reply
    mg_ws_send(conn, (const char *) strResult.c_str(), strResult.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                              COPYRIGHT
  //-------------------------------------------------------------------------

  else if (vscp_startsWith(strTok, "COPYRIGHT")) {
    std::string strvalue;

    std::string strResult = ("+;COPYRIGHT;");
    strResult += VSCPL2DRV_WEBSOCKSRV_COPYRIGHT;

    // Positive reply
    mg_ws_send(conn, (const char *) strResult.c_str(), strResult.length(), WEBSOCKET_OP_TEXT);
  }
  else {
    std::string strResult = "-;";
    strResult += strTok;
    strResult += vscp_str_format(";%d;%s", (int) WEBSOCK_ERROR_UNKNOWN_COMMAND, WEBSOCK_STR_ERROR_UNKNOWN_COMMAND);

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
//   int reject = 1;

//   // Check pointers
//   if (NULL == conn) {
//     return reject;
//   }

//   CWebSockSession *pSession = new CWebSockSession();
//   if (NULL != pSession) {
//     reject = 0;
//     return reject;
//   }

//   // This is a WS2 type connection
//   pSession->setWsType(WS_TYPE_2);

//   spdlog::debug("[Websocket ws2] WS2 Connection: client {}", (reject ? "rejected" : "accepted"));

//   return reject;
// }

////////////////////////////////////////////////////////////////////////////////
// ws2_closeHandler
//

void
CWebSockSrv::ws2_closeHandler(const struct mg_connection *conn, void *cbdata)
{
  if (NULL == conn) {
    return;
  }

  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) conn->fn_data;
  if (NULL == pWebSockSrv) {
    spdlog::error("websockWorkerThread: Invalid CWebSockSrv pointer.");
    return;
  }

  CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
  if (NULL == pSession) {
    return;
  }

  if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
    return;
  }

  // Record activity
  pSession->setLastActiveTime(time(NULL));

  pSession->setConnState(WEBSOCK_CONN_STATE_NULL);
  pSession->setConnection(NULL);

  pthread_mutex_lock(&m_mutex_websocketSession);
  removeSession(conn->id);
  delete pSession;
  pthread_mutex_unlock(&m_mutex_websocketSession);
}

#define WS2_AUTH0_TEMPLATE                                                                                             \
  "{"                                                                                                                  \
  "    \"type\" : \"+\", "                                                                                             \
  "    \"args\" : [\"AUTH0\",\"%s\"]"                                                                                  \
  "}"

////////////////////////////////////////////////////////////////////////////////
// ws2_readyHandler
//

void
CWebSockSrv::ws2_readyHandler(struct mg_connection *conn, void *cbdata)
{
  // Check pointers
  if (NULL == conn) {
    return;
  }

  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) conn->fn_data;
  if (NULL == pWebSockSrv) {
    spdlog::error("websockWorkerThread: Invalid CWebSockSrv pointer.");
    return;
  }

  CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
  if (NULL == pSession) {
    return;
  }

  if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
    return;
  }

  // Record activity
  pSession->setLastActiveTime(time(NULL));

  // Start authentication
  /* Auth0 response
      {
          "type" : "+"
          "args" : ["AUTH0","%s"]
      }
  */
  std::string str = vscp_str_format(WS2_AUTH0_TEMPLATE, pSession->getSid());
  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  spdlog::debug("[Websocket ws2] WS2 AUTH0: client {}", pSession->getSid());

  pSession->setConnState(WEBSOCK_CONN_STATE_DATA);
}

////////////////////////////////////////////////////////////////////////////////
// ws2_dataHandler
//

int
CWebSockSrv::ws2_dataHandler(struct mg_connection *conn, struct mg_ws_message *wm /*, void *cbdata*/)
{
  std::string strWsPkt;

  // Check pointers
  if (NULL == conn) {
    return VSCP_ERROR_ERROR;
  }

  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) conn->fn_data;
  if (NULL == pWebSockSrv) {
    spdlog::error("websockWorkerThread: Invalid CWebSockSrv pointer.");
    return VSCP_ERROR_ERROR;
  }

  CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
  if (NULL == pSession) {
    return VSCP_ERROR_ERROR;
  }

  if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED) {
    return VSCP_ERROR_ERROR;
  }

  // Record activity
  pSession->setLastActiveTime(time(NULL));

  switch (wm->flags & 0x0F) {

    case WEBSOCKET_OP_CONTINUE:

      spdlog::debug("Websocket WS2 - opcode = Continuation");

      // Save and concatenate message parts
      pSession->addConcatenatedString(wm->data);
      break;

    // https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
    case WEBSOCKET_OP_TEXT:
      spdlog::debug("Websocket WS2 - opcode = text[{}]", strWsPkt.c_str());
      if (wm->flags & WEBSOCKET_OP_FINAL) {
        // Last part of message - get all parts
        pSession->addConcatenatedString(wm->data);
        strWsPkt = pSession->getConcatenatedString();
        pSession->clearConcatenatedString();
      }
      else {
        // Not last part - just add to existing parts
        pSession->addConcatenatedString(wm->data);
        return VSCP_ERROR_SUCCESS;
      }

      if (!ws2_message(conn, strWsPkt)) {
        return VSCP_ERROR_ERROR;
      }
      break;

    case WEBSOCKET_OP_BINARY:
      spdlog::debug("Websocket WS2 - opcode = BINARY");
      break;

    case WEBSOCKET_OP_CLOSE:
      spdlog::debug("Websocket WS2 - opcode = Connection close");
      break;

    case WEBSOCKET_OP_PING:
      spdlog::debug("Websocket WS2 - opcode = Ping");
      mg_ws_send(conn, NULL, 0, WEBSOCKET_OP_PONG);
      break;

    case WEBSOCKET_OP_PONG:
      spdlog::debug("Websocket WS2 - Pong received/Pong sent,");
      mg_ws_send(conn, NULL, 0, WEBSOCKET_OP_PING);
      break;

    default:
      break;
  }

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

  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) conn->fn_data;
  if (NULL == pWebSockSrv) {
    spdlog::error("websockWorkerThread: Invalid CWebSockSrv pointer.");
    return false;
  }

  CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
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
          spdlog::error("Failed to parse ws2 websocket command object {0}", strWsPkt.c_str());
          return false;
        }
        catch (...) {
          std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                            strCmd.c_str(),
                                            WEBSOCK_ERROR_PARSE_FORMAT,
                                            WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          spdlog::error("Failed to parse ws2 websocket command object {0}", strWsPkt.c_str());

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
              if (!pSession->isAuthenticated()) {

                str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                      "EVENT",
                                      (int) WEBSOCK_ERROR_NOT_AUTHORISED,
                                      WEBSOCK_STR_ERROR_NOT_AUTHORISED);

                mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                spdlog::error("[Websocket ws2] User {0} is not "
                              "allowed to login.\n",
                              pSession->getUserItem()->getUserName().c_str());

                return false; // 'false' - Drop connection
              }

              vscpEventEx ex;
              if (vscp_convertJSONToEventEx(&ex, str)) {

                // If GUID is all null give it GUID of interface
                if (vscp_isGUIDEmpty(ex.GUID)) {
                  pSession->getGuid()->writeGUID(ex.GUID);
                }

                // Is this user allowed to send events
                if (!(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  spdlog::error("[Websocket ws2] User {0} is not "
                                "allowed to send events.\n",
                                pSession->getUserItem()->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS1.PROTOCOLevents
                if ((VSCP_CLASS1_PROTOCOL == ex.vscp_class) && (VSCP_CLASS2_LEVEL1_PROTOCOL == ex.vscp_class) &&
                    !(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_L1CTRL_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  spdlog::error("[Websocket ws2] User {0} is not "
                                "authorised to send CLASS1.PROTOCOL "
                                "events.\n",
                                pSession->getUserItem()->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS2.PROTOCOL events
                if ((VSCP_CLASS2_PROTOCOL == ex.vscp_class) &&
                    !(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_L2CTRL_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  spdlog::error("[Websocket ws2] User {0} is not "
                                "authorised to send CLASS2.PROTOCOL "
                                "events.\n",
                                pSession->getUserItem()->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Is user allowed to send CLASS2.HLO events
                if ((VSCP_CLASS2_HLO == ex.vscp_class) &&
                    !(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_SEND_HLO_EVENT)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  spdlog::error("[Websocket ws2] User {0} is not "
                                "authorised to send CLASS2.HLO "
                                "events.\n",
                                pSession->getUserItem()->getUserName().c_str());

                  return true; // 'true' leave connection open
                }

                // Check if this user is allowed to send this event
                if (!pSession->getUserItem()->isUserAllowedToSendEvent(ex.vscp_class, ex.vscp_type)) {

                  std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                                    "EVENT",
                                                    WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                                    WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

                  spdlog::error("[websocket ws2] User {0} is not allowed to "
                                "send event class={1} type={2}.",
                                pSession->getUserItem()->getUserName().c_str(),
                                ex.vscp_class,
                                ex.vscp_type);

                  return true; // 'true' leave connection open
                }

                ex.obid = conn->id; // Set the obid

                if (0 == ex.timestamp) {               // If no timestamp is set
                  ex.timestamp = vscp_makeTimeStamp(); // Set timestamp
                }

                // Put event on input queue of client
                if (VSCP_ERROR_SUCCESS == addEvent2ReceiveQueue(ex)) {
                  str = vscp_str_format(WS2_POSITIVE_RESPONSE, "EVENT", "null");
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
                  spdlog::debug("Sent ws2 event {}", strWsPkt.c_str());
                }
                else {
                  str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        "EVENT",
                                        (int) WEBSOCK_ERROR_TX_BUFFER_FULL,
                                        WEBSOCK_STR_ERROR_TX_BUFFER_FULL);
                  mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
                  spdlog::error("Transmission buffer is full {0}", strWsPkt.c_str());
                  return true; // 'true' leave connection open
                }

                // Sent to all other clients
                for (struct mg_connection *wc = conn->mgr->conns; wc != NULL; wc = wc->next) {

                  if (wc == conn) {
                    continue; // Don't send it back to the sender
                  }

                  if (NULL == wc->pfn_data) {
                    // Write it out
                    if (WS_TYPE_2 == pSession->getWsType()) {
                      std::string str;
                      if (vscp_convertEventExToJSON(str, &ex)) {
                        mg_ws_send(wc, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
                      }
                    }
                  }
                }
              } // convert from JSON
            }
          }
        }
        catch (...) {
          std::string str =
            vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_PARSE_FORMAT, WEBSOCK_STR_ERROR_PARSE_FORMAT);
          mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

          spdlog::error("Failed to parse ws2 websocket event object {0}", strWsPkt.c_str());

          return true; // 'true' leave connection open
        }
      } // 'E'
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

          spdlog::error("Failed to parse ws2 websocket + response object {0}", strWsPkt.c_str());
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

          spdlog::error("Failed to parse ws2 websocket - response object {0}", strWsPkt.c_str());
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

          spdlog::error("Failed to parse ws2 websocket variable object {0}", strWsPkt.c_str());
          return true; // 'true' leave connection open
        }
      }
      else {
        std::string str =
          vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_UNKNOWN_TYPE, WEBSOCK_STR_ERROR_UNKNOWN_TYPE);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        // This is a type we do not recognize
        spdlog::error("Unknown ws2 websocket type {0}", strWsPkt.c_str());
        return true; // 'true' leave connection open
      }
    }
  }
  catch (...) {
    std::string str =
      vscp_str_format(WS2_NEGATIVE_RESPONSE, "EVENT", WEBSOCK_ERROR_UNKNOWN_TYPE, WEBSOCK_STR_ERROR_UNKNOWN_TYPE);
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

    spdlog::error("Failed to parse ws2 websocket command {0}", strWsPkt.c_str());
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

  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) conn->fn_data;
  if (NULL == pWebSockSrv) {
    spdlog::error("websockWorkerThread: Invalid CWebSockSrv pointer.");
    return false;
  }

  CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
  if (NULL == pSession) {
    return false;
  }

  spdlog::debug("[Websocket ws2] Command = {}", strCmd.c_str());

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

    spdlog::error("[Websocket ws2] SETFILTER parse error = {0}", jsonObj.dump().c_str());

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
    if (!pSession->isAuthenticated()) {

      // Start authentication
      std::string strSessionId = vscp_str_format("{\"sid\": \"%s\"}", pSession->getSid());
      std::string str          = vscp_str_format(WS2_POSITIVE_RESPONSE, "CHALLENGE", strSessionId.c_str());
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
    if (authentication(conn, strCrypto, strIV)) {
      std::string userSettings;
      pSession->getUserItem()->getAsString(userSettings);
      str = vscp_str_format(WS2_POSITIVE_RESPONSE, "AUTH", "null");
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
    }
    else {
      str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                            "AUTH",
                            (int) WEBSOCK_ERROR_NOT_AUTHORISED,
                            WEBSOCK_STR_ERROR_NOT_AUTHORISED);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      pSession->setAuthenticated(false); // Not authenticated
    }
  }

  // ------------------------------------------------------------------------
  //                                OPEN
  //-------------------------------------------------------------------------

  else if ("OPEN" == strCmd) {

    // Must be authorised to do this
    if (!pSession->isAuthenticated()) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        "OPEN",
                                        (int) WEBSOCK_ERROR_NOT_AUTHORISED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORISED);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      return false; // We still leave channel open
    }

    pSession->setOpen(true);
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, "OPEN", "null");
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                                CLOSE
  //-------------------------------------------------------------------------

  else if ("CLOSE" == strCmd) {
    pSession->setOpen(false);
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, "CLOSE", "null");
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                             SETFILTER/SF
  //-------------------------------------------------------------------------

  else if (("SETFILTER" == strCmd) || ("SF" == strCmd)) {

    std::string strFilter;
    unsigned char ifGUID[16];
    memset(ifGUID, 0, 16);

    // Must be authorised to do this
    if (!pSession->isAuthenticated()) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_AUTHORISED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORISED);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      spdlog::error("[Websocket w2] User/host is not authorised to set a filter.");

      return false; // We still leave channel open
    }

    // Check privilege
    if (!(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_SETFILTER)) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_ALLOWED_TO_DO_THAT,
                                        WEBSOCK_STR_ERROR_NOT_ALLOWED_TO_DO_THAT);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      spdlog::error("[Websocket w2] User {0} is not "
                    "allowed to set a filter.\n",
                    pSession->getUserItem()->getUserName().c_str());
      return false; // We still leave channel open
    }

    // Get filter
    if (!argmap.empty()) {

      strFilter = jsonObj.dump();

      pthread_mutex_lock(&pSession->m_mutexInputQueue);
      if (!vscp_readFilterMaskFromJSON(pSession->getFilter(), strFilter)) {

        std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                          strCmd.c_str(),
                                          (int) WEBSOCK_ERROR_SYNTAX_ERROR,
                                          WEBSOCK_STR_ERROR_SYNTAX_ERROR);
        mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

        spdlog::error("[Websocket w2] Set filter syntax error. [{0}]", strFilter.c_str());

        pthread_mutex_unlock(&pSession->m_mutexInputQueue);
        return false;
      }

      pthread_mutex_unlock(&pSession->m_mutexInputQueue);
    }
    else {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_SYNTAX_ERROR,
                                        WEBSOCK_STR_ERROR_SYNTAX_ERROR);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      spdlog::error("[Websocket w2] Set filter syntax error. [{0}]", strFilter.c_str());

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
    if (!pSession->isAuthenticated()) {

      std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                        strCmd.c_str(),
                                        (int) WEBSOCK_ERROR_NOT_AUTHORISED,
                                        WEBSOCK_STR_ERROR_NOT_AUTHORISED);
      mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);

      spdlog::error("[Websocket w2] User/host is not authorised to clear the queue.");

      return false; // We still leave channel open
    }

    std::deque<vscpEvent *>::iterator it;
    pthread_mutex_lock(&pSession->m_mutexInputQueue);

    for (it = pSession->m_inputQueue.begin(); it != pSession->m_inputQueue.end(); ++it) {
      vscpEvent *pEvent = pSession->m_inputQueue.front();
      pSession->m_inputQueue.pop_front();
      vscp_deleteEvent_v2(&pEvent);
    }

    pSession->m_inputQueue.clear();
    pthread_mutex_unlock(&pSession->m_mutexInputQueue);

    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), "null");
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }

  // ------------------------------------------------------------------------
  //                              VERSION
  //-------------------------------------------------------------------------

  else if (("VERSION" == strCmd) || ("VER" == strCmd)) {

    // std::string strvalue;
    std::string strResult;
    strResult = vscp_str_format("{ \"version\" : \"%d.%d.%d-%d\" }",
                                VSCP_WS2_PROTOCOL_VERSION,
                                VSCP_WS2_PROTOCOL_MINOR_VERSION,
                                VSCP_WS2_PROTOCOL_RELEASE_VERSION,
                                VSCP_WS2_PROTOCOL_BUILD_VERSION);
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
    // strResult += VSCPD_COPYRIGHT;
    strResult += "\" }";

    // Positive reply
    std::string str = vscp_str_format(WS2_POSITIVE_RESPONSE, strCmd.c_str(), strResult.c_str());
    mg_ws_send(conn, (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
  }
  else {
    std::string str = vscp_str_format(WS2_NEGATIVE_RESPONSE,
                                      strCmd.c_str(),
                                      (int) WEBSOCK_ERROR_UNKNOWN_COMMAND,
                                      WEBSOCK_STR_ERROR_UNKNOWN_COMMAND);
    spdlog::error("[Websocket w2] Unknown command [{0}].", strCmd.c_str());

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

  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) conn->fn_data;
  if (NULL == pWebSockSrv) {
    spdlog::error("websockWorkerThread: Invalid CWebSockSrv pointer.");
    return VSCP_ERROR_ERROR;
  }

  CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
  if (NULL == pSession) {
    return VSCP_ERROR_INVALID_POINTER;
  }

#ifdef __VSCP_DEBUG_WEBSOCKET
  spdlog::error("[Websocket ws2] Command = {0}", strCmd.c_str());
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

// int
// CWebSockSrv::websock_post_incomingEvents(void)
// {
//   pthread_mutex_lock(&m_mutex_websocketSession);

//   std::list<CWebSockSession *>::iterator iter;
//   for (iter = gpobj->m_websocketSessions.begin(); iter != gpobj->m_websocketSessions.end(); ++iter) {

//     CWebSockSession *pSession = *iter;
//     if (NULL == pSession) {
//       continue;
//     }

//     // Should be a client item... hmm.... client disconnected
//     if (NULL == pSession->getClientItem()) {
//       continue;
//     }

//     if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED)
//       continue;

//     if (pSession->getClientItem()->m_bOpen && pSession->getClientItem().size()) {

//       vscpEvent *pEvent;
//       pthread_mutex_lock(&pSession->m_mutexInputQueue);
//       pEvent = pSession->getClientItem().front();
//       pSession->getClientItem().pop_front();
//       pthread_mutex_unlock(&pSession->m_mutexInputQueue);
//       if (NULL != pEvent) {

//         // Run event through filter
//         if (vscp_doLevel2Filter(pEvent, &pSession->getClientItem()->m_filter)) {

//           // User must be authorised to receive events
//           if (!(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
//             continue;
//           }

//           std::string str;
//           if (vscp_convertEventToString(str, pEvent)) {

//             spdlog::debug("Received ws event {}", str.c_str());

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
// return VSCP_ERROR_SUCCESS;
// }

///////////////////////////////////////////////////////////////////////////////
// sendEventAllClients
//

// int
// CWebSockSrv::sendEventAllClients(const vscpEvent *pEvent)
// {
//   if (NULL == pEvent) {
//     return VSCP_ERROR_INVALID_POINTER;
//   }

//   // pthread_mutex_lock(&gpobj->m_mutex_websocketSession);

//   //   std::list<CWebSockSession *>::iterator iter;
//   //   for (iter = gpobj->m_websocketSessions.begin(); iter != gpobj->m_websocketSessions.end(); ++iter) {

//   //     CWebSockSession *pSession = *iter;
//   //     if (NULL == pSession) {
//   //       continue;
//   //     }

//   //     // Should be a client item... hmm.... client disconnected
//   //     if (NULL == pSession->getClientItem()) {
//   //       continue;
//   //     }

//   //     if (pSession->getConnState() < WEBSOCK_CONN_STATE_CONNECTED)
//   //       continue;

//   //     if (NULL == pSession->getConn())
//   //       continue;

//   //     if (pSession->getClientItem()->m_bOpen) {

//   //       // Run event through filter
//   //       if (vscp_doLevel2Filter(pEvent, &pSession->getClientItem()->m_filter)) {

//   //         // User must be authorised to receive events
//   //         if (!(pSession->getUserItem()->getUserRights() & VSCP_USER_RIGHT_ALLOW_RCV_EVENT)) {
//   //           continue;
//   //         }

//   //         std::string str;
//   //         if (vscp_convertEventToString(str, pEvent)) {

//           spdlog::debug("Received ws event {}", str.c_str());

//   //           // Write it out
//   //           if (WS_TYPE_1 == pSession->m_wstypes) {
//   //             str = ("E;") + str;
//   //             //mg_websocket_write(pSession->getConn(), (const char *) str.c_str(), str.length());
//   //           }
//   //           else if (WS_TYPE_2 == pSession->m_wstypes) {
//   //             std::string strEvent;
//   //             vscp_convertEventToJSON(strEvent, pEvent);
//   //             std::string str = vscp_str_format(WS2_EVENT, strEvent.c_str());
//   //             //mg_websocket_write(pSession->getConn(), (const char *) str.c_str(), str.length());
//   //           }
//   //         }
//   //       }

//   //     } // events available

//   //   } // for

//   // pthread_mutex_unlock(&gpobj->m_mutex_websocketSession);

//   return VSCP_ERROR_SUCCESS;
// }

//////////////////////////////////////////////////////////////////////////////
// addClient
//

// bool
// CWebSockSrv::addClient(CClientItem *pClientItem, uint32_t id)
// {
//   // Check pointer
//   if (NULL == pClientItem) {
//     return false;
//   }

//   // Add client to client list
//   if (!m_clientList.addClient(pClientItem, id)) {
//     return false;
//   }

//   // Set GUID for interface
//   pClientItem->m_guid = m_guid;

//   // Fill in client id
//   pClientItem->m_guid.setNicknameID(0);
//   pClientItem->m_guid.setClientID(pClientItem->m_clientID);

//   return true;
// }

//////////////////////////////////////////////////////////////////////////////
// addClient - GUID (for drivers with set GUID)
//

// bool
// CWebSockSrv::addClient(CClientItem *pClientItem, cguid &guid)
// {
//   // Check pointer
//   if (NULL == pClientItem) {
//     return false;
//   }

//   // Add client to client list
//   if (!m_clientList.addClient(pClientItem, guid)) {
//     return false;
//   }

//   return true;
// }

//////////////////////////////////////////////////////////////////////////////
// removeClient
//

// void
// CWebSockSrv::removeClient(CClientItem *pClientItem)
// {
//   // Do not try to handle invalid clients
//   if (NULL == pClientItem) {
//     return;
//   }

//   // Remove the client
//   m_clientList.removeClient(pClientItem);
// }

/////////////////////////////////////////////////////////////////////////////
// generateSessionId
//

// bool
// CWebSockSrv::generateSessionId(const char *pKey, char *psid)
// {
//   char buf[8193];

//   // Check pointers
//   if (NULL == pKey) {
//     return false;
//   }
//   if (NULL == psid) {
//     return false;
//   }
//   // Check key length
//   if (strlen(pKey) > 256) {
//     return false;
//   }

//   // Generate a random session ID
//   time_t t;
//   t = time(NULL);
//   snprintf(buf,
//            sizeof(buf),
//            "__%s_%X%X%X%X_be_hungry_stay_foolish_%X%X",
//            pKey,
//            (unsigned int) rand(),
//            (unsigned int) rand(),
//            (unsigned int) rand(),
//            (unsigned int) t,
//            (unsigned int) rand(),
//            1337);

//   vscp_md5(psid, (const unsigned char *) buf, strlen(buf));

//   return true;
// }

/////////////////////////////////////////////////////////////////////////////
// readEncryptionKey
//

bool
CWebSockSrv::readEncryptionKey(const std::string &path)
{
  // TODO Key is in session object
  try {
    // uint8_t key[33];
    std::ifstream in(path, std::ifstream::in);
    std::stringstream strStream;
    strStream << in.rdbuf();
    size_t cnt = vscp_hexStr2ByteArray(m_encryptionKey, 32, strStream.str().c_str());
    if (cnt != 32) {
      spdlog::error("Encryption key file [{0}] is invalid.", getKeyPath().c_str());
      in.close();
      return false;
    }

    in.close();
  }
  catch (...) {
    spdlog::error("Failed to read encryption key file [{0}]", getKeyPath().c_str());
    return false;
  }

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
// websocksrv_event_handler
//
// SERVER event handler
// This RESTful server implements the following endpoints:
//   /ws1 - upgrade to Websocket, and implement ws1 server
//   /ws2 - upgrade to Websocket, and implement ws2 server
//   /rest - respond with JSON string {"result": 123}
//   any other URI serves static files from web root directory

static void
websocksrv_event_handler(struct mg_connection *conn, int mgev, void *ev_data)
{
  // Check pointers
  if (NULL == conn) {
    spdlog::error("Communication context is NULL.");
    return;
  }

  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) conn->fn_data;
  if (NULL == pWebSockSrv) {
    spdlog::error("websocksrv_event_handler: Invalid CWebSockSrv pointer.");
    return;
  }

  struct mg_tls_opts *tls_opts = NULL;

  if ((mgev == MG_EV_OPEN) && (conn->is_listening == 1)) {
    // conn->is_hexdumping = 1;
    spdlog::debug("WebSockSrv is listening.");
  }
  else if (conn->is_tls && (mgev == MG_EV_ACCEPT)) {
    spdlog::debug("WebSockSrv accepted connection.");
    if (mg_url_is_ssl(pWebSockSrv->m_j_config["interface"].get<std::string>().c_str())) {
      struct mg_tls_opts opts = { .cert = mg_unpacked(pWebSockSrv->getCertPath().c_str()),
                                  .key  = mg_unpacked(pWebSockSrv->getKeyPath().c_str()) };
      mg_tls_init(conn, &opts);
    }
    else {
      spdlog::error("websocksrv_event_handler: TLS connection on non-TLS port.");
      conn->is_closing = 1;
      return;
    }
  }
  else if (MG_EV_HTTP_MSG == mgev) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

    // Get protocol version and sec-key
    struct mg_str *header;
    char pws_version[10];
    memset(pws_version, 0, sizeof(pws_version));
    if (NULL != (header = mg_http_get_header(hm, "Sec-WebSocket-Version"))) {
      size_t copyLen = (header->len < sizeof(pws_version) - 1) ? header->len : sizeof(pws_version) - 1;
      strncpy(pws_version, header->buf, copyLen);
    }

    char pws_key[33];
    memset(pws_key, 0, sizeof(pws_key));
    if (NULL != (header = mg_http_get_header(hm, "Sec-WebSocket-Key"))) {
      size_t copyLen = (header->len < sizeof(pws_key) - 1) ? header->len : sizeof(pws_key) - 1;
      strncpy(pws_key, header->buf, copyLen);
    }

    // "/ws1"
    if (pWebSockSrv->isEnableWS1() && mg_match(hm->uri, mg_str(pWebSockSrv->getWs1Url().c_str()), NULL)) {

      // Upgrade to websocket (ws1 protocol). From now on, a connection is a full-duplex
      // Websocket connection, which will receive MG_EV_WS_MSG events.
      mg_ws_upgrade(conn, hm, NULL);

      CWebSockSession *pSession = pWebSockSrv->newSession(conn->id, pws_version, pWebSockSrv->getEncryptionKey());
      if (NULL == pSession) {
        spdlog::error("websocksrv_event_handler: Failed to create CWebSockSession instance.");
        mg_http_reply(conn, 500, "", "Internal Server Error - closing connection\n");
        conn->is_closing = 1;
        return;
      }

      // save connection
      pSession->setConnection(conn);

      // Set connection type
      pSession->setWsType(WS_TYPE_1);

      // Send AUTH start message
      pWebSockSrv->ws1_readyHandler(conn, pSession);
    }
    // "/ws2"
    else if (pWebSockSrv->isEnableWS2() && mg_match(hm->uri, mg_str(pWebSockSrv->getWs2Url().c_str()), NULL)) {
      // Upgrade to websocket (ws2 protocol). From now on, a connection is a full-duplex
      // Websocket connection, which will receive MG_EV_WS_MSG events.
      mg_ws_upgrade(conn, hm, NULL);

      CWebSockSession *pSession = pWebSockSrv->newSession(conn->id, pws_version, pWebSockSrv->getEncryptionKey());
      if (NULL == pSession) {
        spdlog::error("websocksrv_event_handler: Failed to create CWebSockSession instance.");
        mg_http_reply(conn, 500, "", "Internal Server Error - closing connection\n");
        conn->is_closing = 1;
        return;
      }

      // save connection
      pSession->setConnection(conn);

      // Set connection type
      pSession->setWsType(WS_TYPE_2);

      // Send AUTH start message
      pWebSockSrv->ws2_readyHandler(conn, pSession);
    }
    // "/rest"
    else if (pWebSockSrv->isEnableREST() && mg_match(hm->uri, mg_str(pWebSockSrv->getRestUrl().c_str()), NULL)) {
      // Serve REST response
      mg_http_reply(conn, 200, "", "{\"result\": %d}\n", 123);
    }
    else if (pWebSockSrv->isEnableStatic()) {
      // Serve static files
      spdlog::debug("Serving static file request for {0} from web root {1}",
                    std::string(hm->uri.buf, hm->uri.len).c_str(),
                    pWebSockSrv->getWebRoot().c_str());
      std::string webRoot            = pWebSockSrv->getWebRoot();
      struct mg_http_serve_opts opts = { .root_dir = webRoot.c_str() };
      mg_http_serve_dir(conn, hm, &opts);
    }
  }
  else if (MG_EV_WS_MSG == mgev) {

    // Got websocket frame. Received data is wm->data.
    struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
    // mg_ws_send(conn, wm->data.buf, wm->data.len, WEBSOCKET_OP_TEXT);

    CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);
    if (NULL == pSession) {
      spdlog::error("websocksrv_event_handler: Failed to get session.");
      mg_http_reply(conn, 500, "", "Internal Server Error (Failed to get session.)\n");
      return;
    }

    if (WS_TYPE_1 == pSession->getWsType()) {
      std::string strMsg((const char *) wm->data.buf, wm->data.len);
      pWebSockSrv->ws1_dataHandler(conn, wm);
    }
    else if (WS_TYPE_2 == pSession->getWsType()) {
      std::string strMsg((const char *) wm->data.buf, wm->data.len);
      pWebSockSrv->ws2_dataHandler(conn, wm);
    }
  }
  // Message form another thread has been received
  else if (MG_EV_WAKEUP == mgev) {

    // VSCP Event from API write should be sent to all clients

    // Create new session
    // CWebSockSession *pSession = newSession(conn.id, pws_version, pws_key);
    // if (NULL == pSession) {
    //   spdlog::error("Internal error: sendEvent - pSession == NULL");
    //   return;
    // }

    // Get data pointer
    const struct mg_str *data = (const struct mg_str *) ev_data;
    if (NULL == data) {
      spdlog::error("websocksrv_event_handler: Invalid data pointer.");
      return;
    }

    // Get event pointer
    vscpEvent *pev = (vscpEvent *) data->buf;
    if (NULL == pev) {
      spdlog::error("websocksrv_event_handler: Invalid event pointer.");
      return;
    }

    spdlog::debug("Send message (all clients): %.*s", (int) data->len, data->buf);

    // Traverse over all connections
    for (struct mg_connection *wc = conn->mgr->conns; wc != NULL; wc = wc->next) {

      if (wc->is_websocket == 0) {
        continue; // Not a websocket connection
      }

      if (conn->id == pev->obid) {
        continue; // Don't send to ourself
      }

      CWebSockSession *pSession = pWebSockSrv->getSession(wc->id);
      if (NULL == pSession) {
        continue; // Not our connection
      }

      // Write it out
      if (WS_TYPE_1 == pSession->getWsType()) {
        std::string str;
        if (vscp_convertEventToString(str, pev)) {
          str = ("E;") + str;
          mg_ws_send(pSession->getConnection(), (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
        }
      }
      else if (WS_TYPE_2 == pSession->getWsType()) {
        std::string strEvent;
        vscp_convertEventToJSON(strEvent, pev);
        std::string str = vscp_str_format(WS2_EVENT, strEvent.c_str());
        mg_ws_send(pSession->getConnection(), (const char *) str.c_str(), str.length(), WEBSOCKET_OP_TEXT);
      }
    }

    delete pev; // Free the data buffer allocated in another thread
  }
  else if (MG_EV_CLOSE == mgev) {
    // Connection is closed, free resources
    if (conn->is_tls) {
      mg_tls_free(conn);
    }

    CWebSockSession *pSession = pWebSockSrv->getSession(conn->id);

    // Remove client from client map
    pWebSockSrv->removeSession(conn->id);

    if (NULL == pSession) {
      // Free the session data
      delete pSession;
    }

    spdlog::info("Client removed and connection closed");
  }
}

///////////////////////////////////////////////////////////////////////////////
// websockWorkerThread
//

static void *
websockWorkerThread(void *pData)
{
  CWebSockSrv *pWebSockSrv = (CWebSockSrv *) pData;
  if (NULL == pWebSockSrv) {
    spdlog::error("websockWorkerThread: Invalid CWebSockSrv pointer.");
    return NULL;
  }

  struct mg_mgr mgr; // Event manager
  mg_mgr_init(&mgr); // Initialise event manager
  spdlog::info("Starting WS listener on `{0}`\n", pWebSockSrv->getUrl().c_str());

  // Create HTTP listener (websocket object is in conn->fn_data)
  mg_http_listen(&mgr, pWebSockSrv->getUrl().c_str(), websocksrv_event_handler, pWebSockSrv);

  mg_wakeup_init(&mgr);

  while (!pWebSockSrv->m_bQuit) {
    mg_mgr_poll(&mgr, 100); // Poll for events

    vscpEvent *pEvent = NULL;
#ifdef WIN32
    // Wait for semaphore with 100ms timeout
    if (WaitForSingleObject(pWebSockSrv->m_semSendQueue, 100) == WAIT_OBJECT_0) {
#elif defined(__linux__)
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
      /* handle error */
      continue;
    }
    ts.tv_nsec += 100000000; // 100 ms
    if (ts.tv_nsec >= 1000000000) {
      ts.tv_sec++;
      ts.tv_nsec -= 1000000000;
    }
    if (sem_timedwait(&pWebSockSrv->m_semSendQueue, &ts) == 0) {
#else
    // macOS and other Unix systems - use polling approach
    bool sem_acquired = false;
    for (int i = 0; i < 10; i++) { // Poll for 100ms total (10 * 10ms)
      if (sem_trywait(&pWebSockSrv->m_semSendQueue) == 0) {
        sem_acquired = true;
        break;
      }
      if (errno != EAGAIN) {
        break; // Real error
      }
      usleep(10000); // Sleep 10ms
    }
    if (sem_acquired) {
#endif

      // We have an event to send
      pthread_mutex_lock(&pWebSockSrv->m_mutexSendQueue);
      if (!pWebSockSrv->m_sendQueue.empty()) {
        pEvent = pWebSockSrv->m_sendQueue.front();
        pWebSockSrv->m_sendQueue.pop_front();
      }
      pthread_mutex_unlock(&pWebSockSrv->m_mutexSendQueue);

      // Send event to all clients
      pWebSockSrv->sendEventAllClients(pEvent);
      vscp_deleteEvent_v2(&pEvent);
      pEvent = NULL;
    }
  }

  mg_mgr_free(&mgr);
  return 0;
}
