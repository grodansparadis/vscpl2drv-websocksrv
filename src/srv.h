// srv.h
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

#if !defined(VSCP_TCPIPSRV_H__INCLUDED_)
#define VSCP_TCPIPSRV_H__INCLUDED_

#include <sockettcp.h>
#include "clientlist.h"

#include <deque>

typedef const char* (*COMMAND_METHOD)(void);

// Forward declarations
class CTcpipSrv;
class tcpipClientObj;

#define __VSCP_DEBUG_TCP    1

#define VSCP_TCPIP_SRV_RUN  0
#define VSCP_TCPIP_SRV_STOP 1

#define VSCP_TCPIP_COMMAND_LIST_MAX 200 // Max number of saved old commands



#define VSCP_TCP_MAX_CLIENTS 1024





/*!
    Class that defines one command
*/
typedef struct
{
    std::string m_strCmd;    // Command name
    uint8_t m_securityLevel; // Security level for command (0-15)
} structCommand;

/*!
    This class implement the listen thread for
    the vscpd connections on the TCP interface
*/

class tcpipListenThreadObj
{

  public:
    /// Constructor
    tcpipListenThreadObj(CTcpipSrv* pobj = NULL);

    /// Destructor
    ~tcpipListenThreadObj();

    /*!
        Set listening port
        Examples for IPv4: 80, 443s, 127.0.0.1:3128, 192.0.2.3:8080s
        Examples for IPv6: [::]:80, [::1]:80
    */
    void setListeningPort(const std::string& str) { m_strListeningPort = str; };

    /*!
        Getter/setter for control object
    */
    void setControlObjectPointer(CTcpipSrv* pobj) { m_pObj = pobj; };
    CTcpipSrv* getControlObject(void) { return m_pObj; };

    // This mutex protects the clientlist
    pthread_mutex_t m_mutexTcpClientList;

    // List with active tcp/ip clients
    std::list<tcpipClientObj*> m_tcpip_clientList;

    // Listening port
    std::string m_strListeningPort;

    // Settings for the tcp/ip server
    server_context m_srvctx;

    // Counter for client id's
    unsigned long m_idCounter;

    int m_nStopTcpIpSrv;

    // Pointer to the mother of all things
    CTcpipSrv* m_pObj;
};

// ----------------------------------------------------------------------------

/*!
    This class implement the worker thread for
    the vscpd connections on the TCP interface
*/

class tcpipClientObj
{

  public:
    /// Constructor
    tcpipClientObj(tcpipListenThreadObj* pParent);

    /// Destructor
    ~tcpipClientObj();

    /*!
     * Write string to client
     * If encryption is activated this routine will encrypt
     * the string before sending it,
     * @param str String to write.
     * @param bAddCRLF If true crlf will be added to string
     * @return True on success, false on failure
     */
    bool write(std::string& str, bool bAddCRLF = false);

    /*!
     * Write string to client
     * @param buf Pointer to string to write
     * @param len Number of characters to write.
     * @return True on success, false on failure
     */
    bool write(const char* buf, size_t len);

    /*!
     * read string (crlf terminated) from input queue
     * If encryption is activated the string will be decrypted
     * before it is returned.
     * @param str String that will get read data
     * @return True on success (there is data to read), false on failure
     */
    bool read(std::string& str);

    /*!
        When a command is received on the TCP/IP interface the command handler
       is called.
    */
    int CommandHandler(std::string& strCommand);

    /*!
        Check if a user has been verified
        @return true if verified, else false.
    */
    bool isVerified(void);

    /*!
        Check if a user has enough privilege
        @param reqiredPrivilege Privileges required to do operation.
        @return true if yes, else false.
    */
    bool checkPrivilege(unsigned long reqiredPrivilege);

    /*!
        Client send event
    */
    void handleClientSend(void);

    /*!
        Client receive
    */
    void handleClientReceive(void);

    /*!
        sendOneEventFromQueue
        @param 	bStatusMsg True if response messages (+OK/-OK) should be sent.
       Default.
        @return True on success/false on failure.
    */
    bool sendOneEventFromQueue(bool bStatusMsg = true);

    /*!
        Client DataAvailable
    */
    void handleClientDataAvailable(void);

    /*!
        Client Clear Input queue
    */
    void handleClientClearInputQueue(void);

    /*!
        Client Get statistics
    */
    void handleClientGetStatistics(void);

    /*!
        Client get status
    */
    void handleClientGetStatus(void);

    /*!
        Client get channel GUID
    */
    void handleClientGetChannelGUID(void);

    /*!
        Client set channel ID
    */
    void handleClientSetChannelGUID(void);

    /*!
        Client get version
    */
    void handleClientGetVersion(void);

    /*!
        Client set filter
    */
    void handleClientSetFilter(void);

    /*!
        Client set mask
    */
    void handleClientSetMask(void);

    /*!
        Client issue user
    */
    void handleClientUser(void);

    /*!
    Client issue password
    */
    bool handleClientPassword(void);

    /*!
     Handle challenge
     */
    void handleChallenge(void);

    /*!
        Client Get channel ID
    */
    void handleClientGetChannelID(void);

    /*!
        Handle RcvLoop
    */
    void handleClientRcvLoop(void);

    /*!
          Client Help
      */
    void handleClientHelp(void);

    /*!
          Client Test
      */
    void handleClientTest(void);

    /*!
          Client Restart
      */
    void handleClientRestart(void);

    /*!
        Client Shutdown
    */
    void handleClientShutdown(void);

    /*!
        Client REMOTE command
    */
    void handleClientRemote(void);

    /*!
        Client CLIENT/INTERFACE command
    */
    void handleClientInterface(void);

    /*!
        Client INTERFACE LIST command
    */
    void handleClientInterface_List(void);

    /*!
        Client INTERFACE UNIQUE command
    */
    void handleClientInterface_Unique(void);

    /*!
        Client INTERFACE NORMAL command
    */
    void handleClientInterface_Normal(void);

    /*!
        Client INTERFACE CLOSE command
    */
    void handleClientInterface_Close(void);

    /*!
        Client WhatCanYouDo command
    */
    void handleClientCapabilityRequest(void);

    /*!
     * Handle client measurement
     */
    void handleClientMeasurement(void);

    /*!
        Getter/setter for control object
    */
    void setControlObjectPointer(CTcpipSrv* pobj) { m_pObj = pobj; };
    CTcpipSrv* getControlObject(void) { return m_pObj; };

    // --- Member variables ---

    // Client connection
    struct stcp_connection* m_conn;

    // TCP/IP client thread
    pthread_t m_tcpipClientThread;

    /// Parent object
    tcpipListenThreadObj* m_pParent;

    // Pointer to control object from listen parent
    CTcpipSrv* m_pObj;

    /*!
        Logged in client
    */
    CClientItem *m_pClientItem;

    // All input is added to the receive buf. as it is
    // received. Commands are then fetched from this buffer
    // as we go
    std::string m_strResponse;

    // Saved return value for last sockettcp operation
    size_t m_rv;

    // Flag for receive loop active
    bool m_bReceiveLoop;

    // List of old commands
    std::deque<std::string> m_commandArray;
};

#endif
