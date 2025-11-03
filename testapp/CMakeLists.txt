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
project(testapp LANGUAGES CXX C)
set(PACKAGE_AUTHOR "Ake Hedman, the VSCP Project")

# --- System Libraries ---
include(GNUInstallDirs)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# pthreads
set (THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

#openssl
find_package(OpenSSL REQUIRED)

# Expat C library
find_package(expat CONFIG REQUIRED)

add_executable(${PROJECT_NAME})
target_sources(${PROJECT_NAME} PRIVATE main.cpp
  ../third_party/Mustache/mustache.hpp
  ../third_party/spdlog/include
  ../third_party/vscp/src/vscp/common/guid.h
  ../third_party/vscp/src/vscp/common/guid.cpp 
  ../third_party/vscp/src/vscp/common/vscp.h
  ../third_party/vscp/src/vscp/common/vscpdatetime.h
  ../third_party/vscp/src/vscp/common/vscpdatetime.cpp
  ../third_party/vscp/src/vscp/common/guid.h
  ../third_party/vscp/src/vscp/common/guid.cpp
  ../third_party/vscp/src/vscp/common/vscphelper.h
  ../third_party/vscp/src/vscp/common/vscphelper.cpp
  ../third_party/vscp/src/vscp/common/canal.h
  ../third_party/vscp/src/common/vscpbase64.h
  ../third_party/vscp/src/common/vscpbase64.c
  ../third_party/vscp/src/common/vscp-aes.h
  ../third_party/vscp/src/common/vscp-aes.c
  ../third_party/vscp/src/common/crc.h
  ../third_party/vscp/src/common/crc.c
  ../third_party/vscp/src/common/crc8.h
  ../third_party/vscp/src/common/crc8.c
  ../third_party/vscp/src/common/vscpmd5.h
  ../third_party/vscp/src/common/vscpmd5.c
  ../third_party/crypto-algorithms/sha256.h
  ../third_party/crypto-algorithms/sha256.c)

if (WIN32)  
  
  find_package(pthreads REQUIRED)
  find_path(PTHREAD_INCLUDE_DIR pthread.h)

  include_directories( PUBLIC src/
    ../third_party/vscp/src/vscp/common/  
    ../third_party/vscp/src/common/
    ../third_party/json/single_include/
    ../third_party/spdlog/include/
    ${PThreads4W_INCLUDE_DIR}
    ${CMAKE_BINARY_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${LOCAL_WIN_INCLUDE})
else()
  include_directories( PUBLIC src/
    ../third_party/vscp/src/vscp/common/
    ../third_party/vscp/src/common
    ../third_party/json/single_include/
    ../third_party/spdlog/include/
    ${CMAKE_BINARY_DIR}
    ${OPENSSL_INCLUDE_DIR})
 endif()  

 if (WIN32)
  target_link_libraries(${PROJECT_NAME} PRIVATE     
    PThreads4W::PThreads4W_CXXEXC
    expat::expat
  )
        
else()
  target_link_libraries(${PROJECT_NAME} PRIVATE     
    m
    dl
    Threads::Threads
    expat::expat
    ${EXPAT_LIBRARIES}
  )
endif()