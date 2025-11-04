# CMakeLists.txt
#
# Build instructions for VSCP Works.
#
# Copyright (c) 2000-2025 Åke Hedman, the VSCP Project
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#

cmake_minimum_required(VERSION 3.5)
project(vscpl2drv-websocksrv LANGUAGES CXX C)
set(PACKAGE_AUTHOR "Ake Hedman, the VSCP Project")


# Version settings
if(NOT DEFINED MAJOR_VERSION)
    SET(MAJOR_VERSION "2")
endif()
if(NOT DEFINED MINOR_VERSION)
    SET(MINOR_VERSION "0")
endif()
if(NOT DEFINED PATCH_VERSION)
    SET(PATCH_VERSION "0")
endif()

# Disable abi warnings (nlohmann)
if(WIN32)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
# Add UTF-8 support for spdlog/fmt
  add_compile_options(/utf-8)
else()
SET(GCC_VSCP_COMPILE_FLAGS "-Wno-psabi -D WITH_SYSTEMD")
endif()

# Profiling
#SET(GCC_VSCP_LINK_FLAGS    "-lgcov")

SET(CPACK_PACKAGE_DESCRIPTION "VSCP driver for tcp/ip server")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "VSCP level II Driver for VSCP that export a server interface for the VSCP tcp/ip link protocol")
SET(CPACK_PACKAGE_VENDOR "the VSCP Project")
SET(CPACK_PACKAGE_CONTACT "akhe@vscp.org")

if(NOT DEFINED APP_LOW_NAME)
  set(APP_LOW_NAME "vscpl2drv-websocksrv")
endif()

if(NOT DEFINED APP_NAME)
  set(APP_NAME "VSCPL2DEV-WEBSOCKSRV")
endif()

if(NOT DEFINED APP_URL)
  set(APP_URL "https://github.com/grodansparadis/vscpl2drv-websocksrv")
endif()

if(NOT DEFINED APP_VERSION)
  set(APP_VERSION, "${MAJOR_VERSION}.${MINOR_VERSION}.${PATCH_VERSION}")
endif()

# Man build and install
if(NOT DEFINED WIN32)
  add_subdirectory(man)
endif()

# Test application
add_subdirectory(testapp)

option(USE_SSL "Use SSL" TRUE)

## --- C++20 build flags ---
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

# Build locations
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}")

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

# Default location for VSCP level II drivers
set(VSCP_LEVEL2_DRV_DIR /var/lib/vscp/drivers/level2/)

# Generate position-independent code (-fPIC on UNIX)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --- System Libraries ---
include(GNUInstallDirs)

# --- Path to vscp --- 
if (NOT DEFINED VSCP_PATH)
  set (VSCP_PATH "${PROJECT_SOURCE_DIR}/../vscp")
endif()

if(WIN32)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-DWIN32_LEAN_AND_MEANS)
  add_definitions(-DOPENSSL_API_1_1)
  add_definitions(-D_POSIX_C_SOURCE)    
  add_definitions(-DVCPKG_TARGET_TRIPLET=x64-windows)
  add_definitions(-DMG_TLS=MG_TLS_OPENSSL)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
  set(LIBS_SYSTEM ws2_32)
elseif(UNIX)
  set(LIBS_SYSTEM c stdc++)
  add_definitions(-DMG_TLS=MG_TLS_OPENSSL)
endif()

#   ===========================  cpack  ===========================
IF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")
  INCLUDE(InstallRequiredSystemLibraries)

  IF(WIN32)
    SET(CPACK_SET_DESTDIR OFF)
  ELSE()
    SET(CPACK_SET_DESTDIR ON)
    SET(CPACK_PACKAGING_INSTALL_PREFIX "/var/lib/vscp/drivers")
  ENDIF()

  IF(WIN32)
    SET(CPACK_GENERATOR "NSIS" "ZIP")
  ELSE()
    SET(CPACK_GENERATOR "DEB" "RPM" "TGZ" "ZIP")
  ENDIF()
  
  set(CPACK_PACKAGE_NAME ${APP_LOW_NAME})
  set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY ${APP_NAME})


  SET(CPACK_PACKAGE_VERSION_MAJOR "${MAJOR_VERSION}")
  SET(CPACK_PACKAGE_VERSION_MINOR "${MINOR_VERSION}")
  SET(CPACK_PACKAGE_VERSION_PATCH "${PATCH_VERSION}")
  SET(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")
  SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}_${MAJOR_VERSION}.${MINOR_VERSION}.${CPACK_PACKAGE_VERSION_PATCH}")
  #SET(CPACK_IGNORE_FILES "\\.psd$;/CVS/;/\\.svn/;/\\.git/;\\.swp$;/CMakeLists.txt.user;\\.#;/#;\\.tar.gz$;/CMakeFiles/;CMakeCache.txt;\\.qm$;/build/;\\.diff$;.DS_Store'")
  #set(CPACK_SOURCE_IGNORE_FILES ${CPACK_IGNORE_FILES})

  SET(CPACK_NSIS_INSTALLED_ICON_NAME "${APP_LOW_NAME}.ico")
  SET(CPACK_NSIS_HELP_LINK ${APP_URL})
  SET(CPACK_NSIS_URL_INFO_ABOUT ${APP_URL})
  SET(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

  IF(NOT DEFINED WIN32)
    SET(CPACK_DEBIAN_PACKAGE_DEPENDS " libexpat-dev, libssl-dev")
    SET(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
    SET(CPACK_DEBIAN_PACKAGE_SECTION "network")
    SET(CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
  ENDIF()

  SET(CPACK_COMPONENTS_ALL Libraries ApplicationData)

  # Configure file with custom definitions for NSIS.
  configure_file(
    ${PROJECT_SOURCE_DIR}/resources/nsis/NSIS.definitions.nsh.in
    ${CMAKE_CURRENT_BINARY_DIR}/resources/nsis/NSIS.definitions.nsh
  )

  # Load packaging facilities.
  INCLUDE(CPack)

ENDIF(EXISTS "${CMAKE_ROOT}/Modules/CPack.cmake")


set(CMAKE_INCLUDE_CURRENT_DIR ON)

# Threading support - cross-platform
if(WIN32)
    # On Windows, use PThreads4W
    find_package(PThreads4W REQUIRED)
    set(THREAD_LIBRARIES PThreads4W::PThreads4W_CXXEXC)
    set(PTHREAD_INCLUDE_DIR ${PThreads4W_INCLUDE_DIR})
else()
    # Unix/Linux/macOS - use standard pthread
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    set(THREAD_LIBRARIES Threads::Threads)
endif()

#openssl
find_package(OpenSSL REQUIRED)

# Expat C library
find_package(expat CONFIG REQUIRED)

set(RESOURCE_FILES
        README.md
        forms/index.html)

# Add files to library
add_library(${PROJECT_NAME}
  ./src/vscpl2drv-websocksrv.cpp
  ./src/websocksrv.cpp 
  ./third_party/vscp/src/vscp/common/userlist.h
  ./third_party/vscp/src/vscp/common/userlist.cpp
  ./third_party/mongoose/mongoose.c
  ./third_party/mongoose/mongoose.h
  ./third_party/Mustache/mustache.hpp
  ./third_party/spdlog/include
  ./third_party/vscp/src/vscp/common/vscp.h
  ./third_party/vscp/src/vscp/common/vscpdatetime.h
  ./third_party/vscp/src/vscp/common/vscpdatetime.cpp
  ./third_party/vscp/src/vscp/common/guid.h
  ./third_party/vscp/src/vscp/common/guid.cpp
  ./third_party/vscp/src/vscp/common/vscphelper.h
  ./third_party/vscp/src/vscp/common/vscphelper.cpp
  ./third_party/vscp/src/vscp/common/canal.h
  ./third_party/vscp/src/common/vscpbase64.h
  ./third_party/vscp/src/common/vscpbase64.c
  ./third_party/vscp/src/common/vscp-aes.h
  ./third_party/vscp/src/common/vscp-aes.c
  ./third_party/vscp/src/common/crc.h
  ./third_party/vscp/src/common/crc.c
  ./third_party/vscp/src/common/crc8.h
  ./third_party/vscp/src/common/crc8.c
  ./third_party/vscp/src/common/vscpmd5.h
  ./third_party/vscp/src/common/vscpmd5.c
  ./third_party/crypto-algorithms/sha256.h
  ./third_party/crypto-algorithms/sha256.c
) 

if (WIN32)
    
  find_package(PThreads4W REQUIRED)
  find_path(PTHREAD_INCLUDE_DIR pthread.h)

  include_directories( PUBLIC src/
    ./third_party/vscp/src/vscp/common/  
    ./third_party/vscp/src/common/
    ./third_party/mongoose/
    ./third_party/json/single_include/
    ./third_party/Mustache/
    ./third_party/spdlog/include/
    ${PTHREAD_INCLUDE_DIR}
    ${CMAKE_BINARY_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${LOCAL_WIN_INCLUDE}
 )
else()
  include_directories( PUBLIC src/
    ./third_party/vscp/src/vscp/common/
    ./third_party/vscp/src/common
    ./third_party/mongoose/
    ./third_party/json/single_include/
    ./third_party/Mustache/
    ./third_party/spdlog/include/
    ./third_party/crypto-algorithms/
    ${CMAKE_BINARY_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${LOCAL_SYSLOG_INCLUDE} )
 endif()   

if (WIN32)
  target_link_libraries(${PROJECT_NAME} PRIVATE     
    ${THREAD_LIBRARIES}
    OpenSSL::SSL 
    OpenSSL::Crypto
    OpenSSL::SSL OpenSSL::Crypto
    expat::expat
  )
        
else()
  target_link_libraries(${PROJECT_NAME} PRIVATE     
    m
    dl
    ${THREAD_LIBRARIES}
    OpenSSL::SSL 
    OpenSSL::Crypto
    expat::expat
  )
endif()

# Install
if(WIN32)
  # Runtime files
  install(TARGETS ${PROJECT_NAME}
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )
  # Dependencies
  file(GLOB deps_files "${CMAKE_BINARY_DIR}/Release/*.dll")
  install(FILES ${deps_files} DESTINATION ${CMAKE_INSTALL_BINDIR})
  # LICENSE
  install(FILES "${CMAKE_BINARY_DIR}/../LICENSE" DESTINATION "${CMAKE_INSTALL_BINDIR}/..")
  # README
  install(FILES "${CMAKE_BINARY_DIR}/../README.md" DESTINATION "${CMAKE_INSTALL_BINDIR}/..")
else()
  install(TARGETS ${PROJECT_NAME}
          LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_}${VSCP_LEVEL2_DRV_DIR}
          RUNTIME DESTINATION ${CMAKE_INSTALL_MANDIR}            
          RESOURCE DESTINATION ${CMAKE_INSTALL_FULL_}/var/lib/vscp/vscpd) 
  install(FILES ${CMAKE_SOURCE_DIR}/resources/linux/websocksrv.json
            ${CMAKE_SOURCE_DIR}/resources/linux/users.json
          DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/vscpl2drv-websocksrv/")         
endif()
