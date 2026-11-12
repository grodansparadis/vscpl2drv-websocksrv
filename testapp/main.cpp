// vscp2drv_tcpiplink.cpp : Defines the initialization routines for the DLL.
//
// This file is part of the VSCP (http://www.vscp.org)
//
// Copyright (C) 2000-2025 Ake Hedman,
// Ake Hedman, the VSCP Project, <akhe@vscp.org>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: GPL-2.0-only
//

#ifdef __GNUG__
// #pragma implementation
#endif

#ifdef WIN32
#include "StdAfx.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <dlfcn.h>
#endif

#include <array>
#include <csignal>
#include <cstdint>
#include <iostream>
#include <string>

#include <vscp.h>
#include <vscp-class.h>
#include <vscp-type.h>
#include <guid.h>

#ifdef _WIN32
// Include Windows byteswap compatibility before any VSCP headers
#include "byteswap_compat.h"
#define byteswap_h_included  // Prevent vscphelper.h from including byteswap.h
#endif

#include <vscphelper.h>
#include <level2drvdef.h>

#include <spdlog/async.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

namespace {

volatile std::sig_atomic_t s_stop = 0;

void
handleSignal(int)
{
  s_stop = 1;
}

void
printUsage(const char *program)
{
  std::cout << "Usage: " << program
            << " --driver <driver-library> --config <server-config>"
               " [--guid <16-byte-guid>]\n"
               "\n"
               "Opens the VSCP level II driver. Enable WS1 and WS2 in the\n"
               "server configuration to serve both websocket protocols.\n";
}

} // namespace

int
main(int argc, char *argv[])
{
  std::string driverPath;
  std::string configPath;
  std::string guidString = "FF:FF:FF:FF:FF:FF:FF:FE:00:00:00:00:00:00:00:01";

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      printUsage(argv[0]);
      return 0;
    }

    if ((arg == "--driver" || arg == "--config" || arg == "--guid") &&
        i + 1 < argc) {
      const std::string value = argv[++i];
      if (arg == "--driver") {
        driverPath = value;
      }
      else if (arg == "--config") {
        configPath = value;
      }
      else {
        guidString = value;
      }
      continue;
    }

    std::cerr << "Unknown option or missing option value: " << arg << '\n';
    printUsage(argv[0]);
    return 2;
  }

  if (driverPath.empty() || configPath.empty()) {
    printUsage(argv[0]);
    return 2;
  }

  cguid guid(guidString);

#ifdef WIN32
  HMODULE hdll = LoadLibraryA(driverPath.c_str());
#else
  void *hdll = dlopen(driverPath.c_str(), RTLD_NOW);
#endif
  if (!hdll) {
#ifdef WIN32
    spdlog::error("Unable to load driver library '{}'.", driverPath);
#else
    spdlog::error("Unable to load driver library '{}': {}",
                  driverPath,
                  dlerror());
#endif
    return 1;
  }

  auto getSymbol = [hdll](const char *name) {
#ifdef WIN32
    return reinterpret_cast<void *>(GetProcAddress(hdll, name));
#else
    dlerror();
    return dlsym(hdll, name);
#endif
  };

  auto proc_VSCPOpen =
    reinterpret_cast<LPFNDLL_VSCPOPEN>(getSymbol("VSCPOpen"));
  auto proc_VSCPClose =
    reinterpret_cast<LPFNDLL_VSCPCLOSE>(getSymbol("VSCPClose"));
  auto proc_VSCPWrite =
    reinterpret_cast<LPFNDLL_VSCPWRITE>(getSymbol("VSCPWrite"));
  auto proc_VSCPRead =
    reinterpret_cast<LPFNDLL_VSCPREAD>(getSymbol("VSCPRead"));

  if (!proc_VSCPOpen || !proc_VSCPClose || !proc_VSCPWrite || !proc_VSCPRead) {
    spdlog::error("Driver library is missing one or more required Level II API functions.");
#ifdef WIN32
    FreeLibrary(hdll);
#else
    dlclose(hdll);
#endif
    return 1;
  }

  const long openHandle = proc_VSCPOpen(configPath.c_str(), guid.getGUID());
  if (0 == openHandle) {
    spdlog::error("Unable to open the driver. Check the config path and driver log.");
#ifdef WIN32
    FreeLibrary(hdll);
#else
    dlclose(hdll);
#endif
    return 1;
  }

  std::signal(SIGINT, handleSignal);
  std::signal(SIGTERM, handleSignal);
  spdlog::info("VSCP driver is running. WS1/WS2 listener settings are read from '{}'. Press Ctrl-C to stop.",
               configPath);

  uint32_t counter = 0;
  std::array<uint8_t, 4> eventData{};
  vscpEvent evSend{};
  evSend.vscp_class = VSCP_CLASS1_MEASUREMENT;
  evSend.vscp_type  = VSCP_TYPE_MEASUREMENT_COUNT;
  evSend.timestamp  = vscp_makeTimeStamp();
  evSend.sizeData   = static_cast<uint16_t>(eventData.size());
  evSend.pdata      = eventData.data();

  while (!s_stop) {
    vscpEvent ev{};
    if (CANAL_ERROR_SUCCESS != proc_VSCPRead(openHandle, &ev, 1000)) {
      if (CANAL_ERROR_SUCCESS != proc_VSCPWrite(openHandle, &evSend, 500)) {
        spdlog::warn("Failed to write the demonstration event.");
      }
      counter++;
      eventData[0] = static_cast<uint8_t>((counter >> 24) & 0xff);
      eventData[1] = static_cast<uint8_t>((counter >> 16) & 0xff);
      eventData[2] = static_cast<uint8_t>((counter >> 8) & 0xff);
      eventData[3] = static_cast<uint8_t>(counter & 0xff);
      continue;
    }

    if (0 == ev.timestamp) {
      ev.timestamp = vscp_makeTimeStamp();
    }

    spdlog::info("Received event: class={}, type={}, timestamp={}, data-size={}",
                 ev.vscp_class,
                 ev.vscp_type,
                 ev.timestamp,
                 ev.sizeData);
    vscp_deleteEvent(&ev);
  }

  // Close channel
  proc_VSCPClose(openHandle);

#ifdef WIN32
  FreeLibrary(hdll);
#else
  dlclose(hdll);
#endif
  spdlog::info("VSCP test server stopped.");
  return 0;
}