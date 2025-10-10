// vscp2drv_tcpiplink.cpp : Defines the initialization routines for the DLL.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.
//
// This file is part of the VSCP (http://www.vscp.org)
//
// Copyright (C) 2000-2025 Ake Hedman,
// Ake Hedman, the VSCP Project, <akhe@vscp.org>
//
// This file is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this file see the file COPYING.  If not, write to
// the Free Software Foundation, 59 Temple Place - Suite 330,
// Boston, MA 02111-1307, USA.
//

#ifdef __GNUG__
// #pragma implementation
#endif

#ifdef WIN32
#include "StdAfx.h"
#endif

#include <string>
#include <dlfcn.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <map>

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>

#include <vscp.h>
#include <vscp-class.h>
#include <vscp-type.h>
#include <guid.h>
#include <vscphelper.h>
#include <level2drvdef.h>

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

using namespace std::chrono;

static std::string g_strPath      = "/home/akhe/development/VSCP/vscpl2drv-websocksrv/build/libvscpl2drv-websocksrv.so";
static std::string g_strParameter = "/home/akhe/development/VSCP/vscpl2drv-websocksrv/debug/linux/websocksrv.json";
static cguid g_guid("FF:FF:FF:FF:FF:FF:FF:FE:00:00:00:00:00:00:00:01");

// Level II driver methods
LPFNDLL_VSCPOPEN proc_VSCPOpen;
LPFNDLL_VSCPCLOSE proc_VSCPClose;
LPFNDLL_VSCPWRITE proc_VSCPWrite;
LPFNDLL_VSCPREAD proc_VSCPRead;
LPFNDLL_VSCPGETVERSION proc_VSCPGetVersion;

void *hdll; // Handle to DLL  libvscpl2drv-websocksrv.so

int
main(int argc, char *argv[])
{
  void *hdll;       // Handle to  libvscpl2drv-websocksrv.so
  long openHandle;  // Driver handle
  vscpEvent evSend; // VSCP send event
  vscpEvent *pev;   // VSCP event

  memset(&evSend, 0, sizeof(vscpEvent));
  evSend.vscp_class = VSCP_CLASS1_PROTOCOL;
  evSend.vscp_type  = VSCP_TYPE_PROTOCOL_GENERAL;
  evSend.timestamp  = vscp_makeTimeStamp();
  evSend.sizeData   = 3;
  evSend.pdata      = new uint8_t[3];
  evSend.pdata[0]   = 11;
  evSend.pdata[1]   = 22;
  evSend.pdata[2]   = 33;

  // Now find methods in library
  spdlog::info("Loading level II driver");

  // Load dynamic library
  hdll = dlopen(g_strPath.c_str(), RTLD_LAZY);
  if (!hdll) {
    spdlog::error("Unable to load dynamic library. path = {}", dlerror());
    exit(-1);
  }

  // * * * * VSCP OPEN * * * *
  if (nullptr == (proc_VSCPOpen = (LPFNDLL_VSCPOPEN) dlsym(hdll, "VSCPOpen"))) {
    // Free the library
    spdlog::error("Unable to get dl entry for VSCPOpen.");
    exit(-1);
  }

  // * * * * VSCP CLOSE * * * *
  if (nullptr == (proc_VSCPClose = (LPFNDLL_VSCPCLOSE) dlsym(hdll, "VSCPClose"))) {
    // Free the library
    spdlog::error("Unable to get dl entry for VSCPClose.");
    exit(-1);
  }

  // * * * * VSCPWRITE * * * *
  if (nullptr == (proc_VSCPWrite = (LPFNDLL_VSCPWRITE) dlsym(hdll, "VSCPWrite"))) {
    // Free the library
    spdlog::error("Unable to get dl entry for VSCPWrite.");
    exit(-1);
  }

  // * * * * VSCPREAD * * * *
  if (nullptr == (proc_VSCPRead = (LPFNDLL_VSCPREAD) dlsym(hdll, "VSCPRead"))) {
    // Free the library
    spdlog::error("Unable to get dl entry for VSCPBlockingReceive.");
    exit(-1);
  }

  // * * * * VSCP GET VERSION * * * *
  if (nullptr == (proc_VSCPGetVersion = (LPFNDLL_VSCPGETVERSION) dlsym(hdll, "VSCPGetVersion"))) {
    // Free the library
    spdlog::error("Unable to get dl entry for VSCPGetVersion.");
    exit(-1);
  }

  spdlog::debug("Discovered all methods");

  // -------------------------------------------------------------

  // Open up the L2 driver
  openHandle = proc_VSCPOpen(g_strParameter.c_str(), g_guid.getGUID());

  if (0 == openHandle) {
    // Free the library
    spdlog::error("Unable to open VSCP "
                  " level II driver (path, config file access rights)."
                  " There may be additional info from driver "
                  "in log. If not enable debug flag in drivers config file");
    exit(-1);
  }

  while (true) {

    vscpEvent ev;
    memset(&ev, 0, sizeof(vscpEvent));

    sleep(1);
    continue;

    // Block until event is received
    if (CANAL_ERROR_SUCCESS != proc_VSCPRead(openHandle, pev, 1000)) {
      // Send event
      //proc_VSCPWrite(openHandle, &evSend, 500);
      continue;
    }

    // If timestamp is zero we set it here
    if (0 == ev.timestamp) {
      ev.timestamp = vscp_makeTimeStamp();
    }

    // We have an event - just show something on console
    spdlog::info("Received event: Class: {}, Type: {}, Timestamp: {}, SizeData: {}",
                 ev.vscp_class,
                 ev.vscp_type,
                 ev.timestamp,
                 ev.sizeData);

  } // while

  // Close channel
  proc_VSCPClose(openHandle);

  // Unload dll
  dlclose(hdll);

  // Cleanup
  vscp_deleteEvent(&evSend);
}