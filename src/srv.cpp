// srv.cpp
//
// This file is part of the VSCP (https://www.vscp.org)
//
// The MIT License (MIT)
//
// Copyright © 2000-2025 Ake Hedman, the VSCP Project
// <akhe@vscp.org>
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
// https://wiki.openssl.org/index.php/Simple_TLS_Server
// https://wiki.openssl.org/index.php/SSL/TLS_Client
// https://stackoverflow.com/questions/3919420/tutorial-on-using-openssl-with-pthreads
//

#ifdef WIN32
#include "StdAfx.h"
#endif

#include <list>
#include <string>

#ifdef WIN32
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#ifdef WITH_WRAP
#include <tcpd.h>
#endif

#ifndef DWORD
#define DWORD unsigned long
#endif

#include <sockettcp.h>
#include <vscp.h>
#include <vscpdatetime.h>
#include <vscphelper.h>

#include "srv.h"
#include "tcpipsrv.h"
#include "version.h"

#include <mustache.hpp>
#include <nlohmann/json.hpp> // Needs C++11  -std=c++11

// https://github.com/nlohmann/json
using json = nlohmann::json;
using namespace kainjow::mustache;

#ifdef WIN32
#define STRDUP _strdup
#else
#define STRDUP strdup
#endif

#define WEBSOCKETSRV_INACTIVITY_TIMOUT (3600 * 12)

// Worker threads
void*
websockListenThread(void* pData);
void*
websockClientThread(void* pData);

///////////////////////////////////////////////////////////////////////////////
//                                  GLOBALS
///////////////////////////////////////////////////////////////////////////////

// ****************************************************************************
//                               Listen thread
// ****************************************************************************

///////////////////////////////////////////////////////////////////////////////
// websockListenThreadObj
//
// This thread listens for connection on a TCP socket and starts a new thread
// to handle client requests
//

websockListenThreadObj::websockListenThreadObj(CTcpipSrv* pobj)
{
  // Set the control object pointer
  setControlObjectPointer(pobj);

  m_strListeningPort = "9598";

  // Init. the server comtext structure
  memset(&m_srvctx, 0, sizeof(struct server_context));

  m_nStopTcpIpSrv = VSCP_TCPIP_SRV_RUN;
  m_idCounter     = 0;

  pthread_mutex_init(&m_mutexTcpClientList, NULL);
}

websockListenThreadObj::~websockListenThreadObj()
{
  pthread_mutex_destroy(&m_mutexTcpClientList);
}

///////////////////////////////////////////////////////////////////////////////
// websockListenThread
//

void*
websockListenThread(void* pData)
{
  size_t i;
  struct stcp_connection* conn;
  struct socket* psocket = nullptr;
  struct stcp_secure_options opts;
  struct pollfd* pfd;
  memset(&opts, 0, sizeof(opts));
#ifdef WITH_WRAP
  struct request_info wrap_req;
  char address[1024];
#endif

  websockListenThreadObj* pListenObj = (websockListenThreadObj*)pData;
  if (NULL == pListenObj) {
    spdlog::error(
      "websocket client is missing client object data. Terminating thread.");
    return NULL;
  }

  // create pointer to main object
  CTcpipSrv* pObj = pListenObj->getControlObject();

  // ------------------------------------------------------------------------

  // * * * Init. secure options * * *

  // Certificate
  if (pObj->m_j_config.value("ssl_certificate", "").length()) {
    opts.pem = STRDUP(pObj->m_j_config.value("ssl_certificate", "").c_str());
  }

  // Certificate chain
  if (pObj->m_j_config.value("ssl_certificate_chain", "").length()) {
    opts.chain =
      STRDUP(pObj->m_j_config.value("ssl_certificate_chain", "").c_str());
  }

  opts.verify_peer = pObj->m_j_config.value("ssl_verify_peer", 0);

  // CA path
  if (pObj->m_j_config.value("ssl_ca_path", "").length()) {
    opts.ca_path = STRDUP(pObj->m_j_config.value("ssl_ca_path", "").c_str());
  }

  // CA file
  if (pObj->m_j_config.value("ssl_ca_file", "").length()) {
    opts.chain = STRDUP(pObj->m_j_config.value("ssl_ca_file", "").c_str());
  }

  opts.verify_depth = pObj->m_j_config.value("ssl_verify_depth", 9);
  opts.default_verify_path =
    pObj->m_j_config.value("ssl_default_verify_paths", true);
  opts.protocol_version = pObj->m_j_config.value("ssl_protocol_version", 3);

  // chiper list
  opts.chipher_list = STRDUP(
    pObj->m_j_config
      .value("ssl_cipher_list", "DES-CBC3-SHA:AES128-SHA:AES128-GCM-SHA256")
      .c_str());

  opts.short_trust = pObj->m_j_config.value("ssl_short_trust", false);

  // Init. SSL subsystem
  if (pObj->m_j_config.value("ssl_certificate", "").length()) {
    if (0 == stcp_init_ssl(pListenObj->m_srvctx.ssl_ctx, &opts)) {
      spdlog::error("[websocket srv thread] Failed to init. ssl.\n");
      return NULL;
    }
  }

  // --------------------------------------------------------------------------------------

  // Bind to selected interface
  if (0 == stcp_listening(&pListenObj->m_srvctx,
                          pListenObj->m_strListeningPort.c_str())) {
    spdlog::error("[websocket srv thread] Failed to init listening socket.");
    return NULL;
  }

  spdlog::debug("[websocket srv listen thread] Started.");

  while (!pListenObj->m_nStopTcpIpSrv) {

    pfd = pListenObj->m_srvctx.listening_socket_fds;
    memset(pfd, 0, sizeof(*pfd));
    for (i = 0; i < pListenObj->m_srvctx.num_listening_sockets; i++) {
      pfd[i].fd      = pListenObj->m_srvctx.listening_sockets[i].sock;
      pfd[i].events  = POLLIN;
      pfd[i].revents = 0;
    }

    int pollres;
    if ((pollres = stcp_poll(pfd,
                             pListenObj->m_srvctx.num_listening_sockets,
                             500,
                             &(pListenObj->m_nStopTcpIpSrv))) > 0) {

      for (i = 0; i < pListenObj->m_srvctx.num_listening_sockets; i++) {

        // NOTE(lsm): on QNX, poll() returns POLLRDNORM after the
        // successful poll, and POLLIN is defined as
        // (POLLRDNORM | POLLRDBAND)
        // Therefore, we're checking pfd[i].revents & POLLIN, not
        // pfd[i].revents == POLLIN.
        if (pfd[i].revents & POLLIN) {

          conn = stcp_new_connection(); // Init connection
          if (NULL == conn) {
            spdlog::error("[websocket srv] -- Memory problem when creating "
                          "conn object.");
            continue;
          }

          memset(conn, 0, sizeof(struct stcp_connection));

          // idCounter is obid for websocket channel
          pListenObj->m_idCounter++;
          if (!pListenObj->m_idCounter) {
            pListenObj->m_idCounter = 1;
          }
          conn->client.id = pListenObj->m_idCounter;

          if (stcp_accept(&pListenObj->m_srvctx,
                          &pListenObj->m_srvctx.listening_sockets[i],
                          &(conn->client))) {

            stcp_init_client_connection(conn, &opts);
            spdlog::debug("[websocket srv] -- Connection accept.");

#ifdef WITH_WRAP
            /* Use tcpd / libwrap to determine whether a connection
             * is allowed. */
            request_init(&wrap_req,
                         RQ_FILE,
                         conn->client.sock,
                         RQ_DAEMON,
                         "vscpl2drv-tcpipsrv",
                         0);
            fromhost(&wrap_req);
            if (!hosts_access(&wrap_req)) {
              // Access is denied
              if (!stcp_socket_get_address(conn, address, 1024)) {
                spdlog::error("Client connection from {} "
                              "denied access by tcpd.",
                              address);
              }
              stcp_close_connection(conn);
              conn = NULL;
              continue;
            }
#endif

            // Create the thread object
            tcpipClientObj* pClientObj = new tcpipClientObj(pListenObj);
            if (NULL == pClientObj) {
              spdlog::error("[websocket srv] -- Memory problem when "
                            "creating client thread.");
              stcp_close_connection(conn);
              conn = NULL;
              continue;
            }

            pClientObj->m_conn    = conn;
            pClientObj->m_pParent = pListenObj;
            spdlog::debug("Controlobject: Starting client websocket thread...");
            int err;
            if ((err = pthread_create(&pClientObj->m_tcpipClientThread,
                                      NULL,
                                      tcpipClientThread,
                                      pClientObj))) {
              spdlog::error("[websocket srv] -- Failed to run client "
                            "websocket client thread. error=%d",
                            err);
              delete pClientObj;
              stcp_close_connection(conn);
              conn = NULL;
              continue;
            }

            // Make it detached
            pthread_detach(pClientObj->m_tcpipClientThread);

            // Add conn to list of active connections
            pthread_mutex_lock(&pListenObj->m_mutexTcpClientList);
            pListenObj->m_tcpip_clientList.push_back(pClientObj);
            pthread_mutex_unlock(&pListenObj->m_mutexTcpClientList);
          }
          else {
            delete psocket;
            psocket = NULL;
          }
        }

      } // for

    } // poll

    pollres = 0;

  } // While

  spdlog::debug("[websocket srv listen thread] Preparing Exit.");

  // Wait for clients to terminate
  int loopCnt = 0;
  while (true) {

    pthread_mutex_lock(&pListenObj->m_mutexTcpClientList);
    if (!pListenObj->m_tcpip_clientList.size())
      break;
    pthread_mutex_unlock(&pListenObj->m_mutexTcpClientList);

    loopCnt++;
#ifndef WIN32
    sleep(1); // Give them some time
#else
    Sleep(1000);
#endif
  }

  stcp_close_all_listening_sockets(&pListenObj->m_srvctx);

  // * * * Deallocate allocated security options * * *

  if (NULL != opts.pem) {
    free((void*)opts.pem);
    opts.pem = NULL;
  }

  if (NULL != opts.chain) {
    free((void*)opts.chain);
    opts.chain = NULL;
  }

  if (NULL != opts.ca_path) {
    free((void*)opts.ca_path);
    opts.ca_path = NULL;
  }

  if (NULL != opts.ca_file) {
    free((void*)opts.ca_file);
    opts.ca_file = NULL;
  }

  if (NULL != opts.chipher_list) {
    free((void*)opts.chipher_list);
    opts.chipher_list = NULL;
  }

  if (pObj->m_j_config.value("ssl_certificate", "").length()) {
    stcp_uninit_ssl();
  }
  spdlog::debug("[websocket srv listen thread] Exit.");
  return NULL;
}

// ****************************************************************************
//                              Client thread
// ****************************************************************************


///////////////////////////////////////////////////////////////////////////////
// Entry
//

void*
websockClientThread(void* pData)
{
  websockClientObj* pwebsockobj = (websockClientObj*)pData;
  if (NULL == pwebsockobj) {
    spdlog::error("[websocket srv client thread] Error, "
                  "Client thread object not initialized.");
    return NULL;
  }

  // if (NULL == pwebsockobj->m_pParent) {
  //   spdlog::error("[websocket srv client thread] Error, "
  //                 "Control object not initialized.");
  //   return NULL;
  // }

  spdlog::debug("[websocket srv client thread] Thread started.");
  pwebsockobj->m_pClientItem = new CClientItem();
  if (NULL == pwebsockobj->m_pClientItem) {
    spdlog::error("[websocket srv client thread] Memory error, "
                  "Cant allocate client structure.");
    return NULL;
  }

  vscpdatetime now;
  pwebsockobj->m_pClientItem->m_dtutc = now;
  pwebsockobj->m_pClientItem->m_bOpen = true;
  pwebsockobj->m_pClientItem->m_type  = CLIENT_ITEM_INTERFACE_TYPE_CLIENT_WEBSOCKET;
  pwebsockobj->m_pClientItem->m_strDeviceName =
    ("Remote websocket server connection @ [");
  pwebsockobj->m_pClientItem->m_strDeviceName +=
    pwebsockobj->m_pObj->m_j_config.value("interface", "127.0.0.1:9598");
  pwebsockobj->m_pClientItem->m_strDeviceName += ("]");

  // Start of activity
  pwebsockobj->m_pClientItem->m_clientActivity = (long)time(NULL);

  // Add the client to the Client List
  pthread_mutex_lock(&pwebsockobj->m_pObj->m_clientList.m_mutexItemList);
  if (!pwebsockobj->m_pObj->addClient(pwebsockobj->m_pClientItem)) {
    // Failed to add client
    delete pwebsockobj->m_pClientItem;
    pwebsockobj->m_pClientItem = NULL;
    pthread_mutex_unlock(&pwebsockobj->m_pObj->m_clientList.m_mutexItemList);
    spdlog::error("websocket server: Failed to add client. Terminating thread.");
    return NULL;
  }
  pthread_mutex_unlock(&pwebsockobj->m_pObj->m_clientList.m_mutexItemList);

  // Clear the filter (Allow everything )
  vscp_clearVSCPFilter(&pwebsockobj->m_pClientItem->m_filter);

  // // Send welcome message
  // std::string str = std::string(MSG_WELCOME);
  // str += std::string("Version: ");
  // str += vscp_str_format("%d.%d.%d-%d",
  //                        MAJOR_VERSION,
  //                        MINOR_VERSION,
  //                        RELEASE_VERSION,
  //                        BUILD_VERSION);
  // str += std::string("\r\n");
  // str += std::string(DRIVER_COPYRIGHT);
  // str += std::string("\r\n");
  // str += std::string(MSG_OK);
  // pwebsockobj->write((const char*)str.c_str(), str.length());
  // spdlog::debug("[websocket srv] Ready to serve client.");

  // Enter command loop
  char buf[8192];
  struct pollfd fd;
  while (true) {

    // Check for client inactivity
    if ((time(NULL) - pwebsockobj->m_pClientItem->m_clientActivity) >
        WEBSOCKSRV_INACTIVITY_TIMOUT) {
      spdlog::info(
        "[websocket srv client thread] Client closed due to inactivity.");
      break;
    }

    // // * * * Receiveloop * * *
    // if (pwebsockobj->m_bReceiveLoop) {

    //   // Wait for data
    //   vscp_sem_wait(&pwebsockobj->m_pClientItem->m_semClientInputQueue, 10);

    //   // Send everything in the queue
    //   while (pwebsockobj->sendOneEventFromQueue(false))
    //     ;

    //   // Send '+OK<CR><LF>' every two seconds to indicate that the
    //   // link is open
    //   if ((time(NULL) - pwebsockobj->m_pClientItem->m_timeRcvLoop) > 2) {
    //     pwebsockobj->m_pClientItem->m_timeRcvLoop    = time(NULL);
    //     pwebsockobj->m_pClientItem->m_clientActivity = (long)time(NULL);
    //     pwebsockobj->write("+OK\r\n", 5);
    //   }
    // }
    // else {


    

    

    // Record client activity
    pwebsockobj->m_pClientItem->m_clientActivity = (long)time(NULL);

    // get data up to "\r\n" if any
    size_t pos;
    if (pwebsockobj->m_strResponse.npos !=
        (pos = pwebsockobj->m_strResponse.find("\n"))) {

      // Get the command
      std::string strCommand = vscp_str_left(pwebsockobj->m_strResponse, pos + 1);

      // Save the unhandled part
      pwebsockobj->m_strResponse =
        vscp_str_right(pwebsockobj->m_strResponse,
                       pwebsockobj->m_strResponse.length() - pos - 1);

      // Remove whitespace
      vscp_trim(strCommand);

      // If nothing to do do nothing - pretty obvious if you think about it
      if (0 == strCommand.length()) {
        continue;
      }

      // Check for repeat command
      // +    - repeat last command
      // +n   - repeat n-th command
      // ++
      if (pwebsockobj->m_commandArray.size() && ('+' == strCommand[0])) {

        if (vscp_startsWith(strCommand, "++", &strCommand)) {
          for (int i = (unsigned int)pwebsockobj->m_commandArray.size() - 1;
               i >= 0;
               i--) {
            std::string str =
              vscp_str_format("%d - %s",
                              pwebsockobj->m_commandArray.size() - i - 1,
                              pwebsockobj->m_commandArray[i].c_str());
            vscp_trim(str);
            pwebsockobj->write(str, true);
          }
          continue;
        }

        // Get pos
        unsigned int n = 0;
        if (strCommand.length() > 1) {
          strCommand = strCommand.substr(strCommand.length() - 1);
          n          = vscp_readStringValue(strCommand);
        }

        // Pos must be within range
        if (n > pwebsockobj->m_commandArray.size()) {
          n = (unsigned int)pwebsockobj->m_commandArray.size() - 1;
        }

        // Get the command
        strCommand =
          pwebsockobj->m_commandArray[pwebsockobj->m_commandArray.size() - n - 1];

        // Write out the command
        pwebsockobj->write(strCommand, true);
      }

      pwebsockobj->m_commandArray.push_back(
        strCommand); // put at beginning of list
      if (pwebsockobj->m_commandArray.size() > VSCP_TCPIP_COMMAND_LIST_MAX) {
        pwebsockobj->m_commandArray.pop_front(); // Remove last inserted item
      }

      // Execute command
      if (VSCP_TCPIP_RV_CLOSE == pwebsockobj->CommandHandler(strCommand)) {
        break;
      }
    }

  } // while

  // Remove the client from the client queue
  pthread_mutex_lock(&pwebsockobj->m_pParent->m_mutexTcpClientList);
  std::list<tcpipClientObj*>::iterator it;
  for (it = pwebsockobj->m_pParent->m_tcpip_clientList.begin();
       it != pwebsockobj->m_pParent->m_tcpip_clientList.end();
       ++it) {

    tcpipClientObj* pclient             = *it; // TODO check
    struct stcp_connection* stored_conn = pclient->m_conn;
    if (stored_conn->client.id == pwebsockobj->m_conn->client.id) {
      pwebsockobj->m_pParent->m_tcpip_clientList.erase(it);
      break;
    }
  }
  pthread_mutex_unlock(&pwebsockobj->m_pParent->m_mutexTcpClientList);

  // Close the connection
  stcp_close_connection(pwebsockobj->m_conn);
  pwebsockobj->m_conn = NULL;

  // Close the channel
  pwebsockobj->m_pClientItem->m_bOpen = false;

  // Remove the client from the Client List
  pthread_mutex_lock(&pwebsockobj->m_pObj->m_clientList.m_mutexItemList);
  pwebsockobj->m_pObj->removeClient(pwebsockobj->m_pClientItem);
  pthread_mutex_unlock(&pwebsockobj->m_pObj->m_clientList.m_mutexItemList);

  pwebsockobj->m_pClientItem = NULL;
  pwebsockobj->m_pParent     = NULL;

  // Delete the client object
  delete pwebsockobj;

  spdlog::debug("[websocket srv client thread] Exit.");

  return NULL;
}
