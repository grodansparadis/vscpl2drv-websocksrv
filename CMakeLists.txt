# CMakeLists.txt
#
# Build instructions for VSCP Works.
#
# Copyright (c) 2000-2025 Åke Hedman and contributors, the VSCP Project
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

# Parse version from version.h file FIRST
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h" VERSION_H_CONTENT)

# Extract and validate the year.month.patch components.
foreach(COMPONENT MAJOR MINOR PATCH)
    string(REGEX MATCH "#define[ \t]+VSCPL2DRV_WEBSOCKSRV_${COMPONENT}_VERSION[ \t]+([0-9]+)" VERSION_MATCH "${VERSION_H_CONTENT}")
    if(NOT VERSION_MATCH)
        message(FATAL_ERROR "Missing or invalid VSCPL2DRV_WEBSOCKSRV_${COMPONENT}_VERSION in src/version.h")
    endif()
    set(VERSION_${COMPONENT} "${CMAKE_MATCH_1}")
endforeach()

# Construct year.month.patch version string.
set(PROJECT_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
set(PROJECT_VERSION_SHORT "${PROJECT_VERSION}")

# Now declare the project with parsed version
project(vscpl2drv-websocksrv VERSION ${PROJECT_VERSION_SHORT} LANGUAGES CXX C)
set(PACKAGE_AUTHOR "Ake Hedman, the VSCP Project")

# Print version information
message(STATUS "Project version: ${PROJECT_VERSION}")
message(STATUS "Version components - Year: ${VERSION_MAJOR}, Month: ${VERSION_MINOR}, Patch: ${VERSION_PATCH}")

# Create cmake directory if it doesn't exist and configure version header
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/cmake")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/version_generated.h"
    @ONLY
)

# Force UTF-8 encoding for MSVC to fix spdlog/fmt Unicode issues
if(MSVC)
    add_compile_options(/utf-8)
    message(STATUS "Added /utf-8 flag for MSVC")
endif()

# Version settings (updated to use parsed values)
if(NOT DEFINED MAJOR_VERSION)
    SET(MAJOR_VERSION "${VERSION_MAJOR}")
endif()
if(NOT DEFINED MINOR_VERSION)
    SET(MINOR_VERSION "${VERSION_MINOR}")
endif()
if(NOT DEFINED PATCH_VERSION)
    SET(PATCH_VERSION "${VERSION_PATCH}")
endif()

# Disable abi warnings (nlohmann)
if(WIN32)
add_definitions(-D_CRT_SECURE_NO_WARNINGS)
add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
# Ensure WIN32 is defined for the preprocessor
add_definitions(-DWIN32)
add_definitions(-D_WIN32)
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
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")

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
  if(APPLE)
    # Suppress deprecation warnings for semaphore functions on macOS
    add_compile_options(-Wno-deprecated-declarations)
  endif()
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


include(FetchContent)

set(VSCP_FETCH_CONTENT_OPTIONS)
if(NOT CMAKE_VERSION VERSION_LESS "3.18")
  list(APPEND VSCP_FETCH_CONTENT_OPTIONS SOURCE_SUBDIR "__vscp_sources_only__")
endif()
if(NOT CMAKE_VERSION VERSION_LESS "3.24")
  list(APPEND VSCP_FETCH_CONTENT_OPTIONS DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
endif()

FetchContent_Declare(
  vscp
  # Only a handful of VSCP source files are compiled directly into vscpd, so
  # there is no need to clone the repository. A pinned source tarball avoids
  # fetching ~1.2GB of git history plus ~400MB of submodules that this project
  # never uses.
  # Get URL_HASH
  # curl -sL https://codeload.github.com/grodansparadis/vscp/tar.gz/<commit> | sha256sum
  URL https://codeload.github.com/grodansparadis/vscp/tar.gz/911239f8fc7a5f084fe3435c6c7f2ee31e9f4c90
  URL_HASH SHA256=a5e1c8154f22139082f857901343580dd510b8fc58c7cfb9d23d6e269cca24fa
  ${VSCP_FETCH_CONTENT_OPTIONS}
)
# Make the VSCP sources available without adding its standalone library targets
# to this build. The daemon compiles only the VSCP source files listed below.
if(CMAKE_VERSION VERSION_LESS "3.18")
  FetchContent_GetProperties(vscp)
  if(NOT vscp_POPULATED)
    FetchContent_Populate(vscp)
  endif()
else()
  FetchContent_MakeAvailable(vscp)
endif()

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.17.0
)
FetchContent_MakeAvailable(spdlog)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.12.0
)
FetchContent_MakeAvailable(nlohmann_json)

FetchContent_Declare(
    mongoose
    GIT_REPOSITORY https://github.com/cesanta/mongoose.git
    GIT_TAG 7.23
)
FetchContent_MakeAvailable(mongoose)

find_package(OpenSSL REQUIRED)
find_library(SODIUM_LIBRARY NAMES sodium)
if(NOT SODIUM_LIBRARY)
  message(FATAL_ERROR "libsodium is required for Argon2id user authentication")
endif()

set(VSCP_COMMON_SOURCES
  ${vscp_SOURCE_DIR}/src/vscp/common/guid.cpp
  ${vscp_SOURCE_DIR}/src/vscp/common/vscpdatetime.cpp
  ${vscp_SOURCE_DIR}/src/vscp/common/vscphelper.cpp
  ${vscp_SOURCE_DIR}/src/common/vscphelper-common.cpp
  ${vscp_SOURCE_DIR}/src/common/vscpbase64.c
  ${vscp_SOURCE_DIR}/src/common/vscp-aes.c
  ${vscp_SOURCE_DIR}/src/common/crc.c
  ${vscp_SOURCE_DIR}/src/common/crc8.c
  ${vscp_SOURCE_DIR}/src/common/vscpmd5.c
)

add_library(vscp-common STATIC ${VSCP_COMMON_SOURCES})
target_include_directories(vscp-common PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${vscp_SOURCE_DIR}/src/vscp/common
  ${vscp_SOURCE_DIR}/src/common
)
if(WIN32)
  target_include_directories(vscp-common PUBLIC
    ${vscp_SOURCE_DIR}/src/common/windows
    ${vscp_SOURCE_DIR}/src/vscp/common/win32helpers
  )
endif()
target_link_libraries(vscp-common PUBLIC
  spdlog::spdlog_header_only
  nlohmann_json::nlohmann_json
  OpenSSL::Crypto
)

# Test application
add_subdirectory(testapp)

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

# Expat C library
if(WIN32)
find_package(expat CONFIG REQUIRED)
else()
include (FindEXPAT)
find_package(EXPAT REQUIRED)
include_directories(${EXPAT_INCLUDE_DIRS})
endif()

# Add application sources to library
add_library(${PROJECT_NAME}
  ./src/vscpl2drv-websocksrv.cpp
  ./src/websocksrv.cpp
  ./src/userlist.cpp
  ${mongoose_SOURCE_DIR}/mongoose.c
)

# NOW add the compile definitions AFTER the target is created
target_compile_definitions(${PROJECT_NAME} PRIVATE
    PROJECT_VERSION_MAJOR=${VERSION_MAJOR}
    PROJECT_VERSION_MINOR=${VERSION_MINOR}
    PROJECT_VERSION_PATCH=${VERSION_PATCH}
    PROJECT_VERSION="${PROJECT_VERSION}"
)

if (WIN32)
  find_package(PThreads4W REQUIRED)
  find_path(PTHREAD_INCLUDE_DIR pthread.h)

  target_include_directories(${PROJECT_NAME} PRIVATE
    ${PTHREAD_INCLUDE_DIR}
    ${CMAKE_BINARY_DIR}
    ${OPENSSL_INCLUDE_DIR}
    "${mongoose_SOURCE_DIR}"
    ${LOCAL_WIN_INCLUDE}
  )
else()
  target_include_directories(${PROJECT_NAME} PRIVATE
    "${mongoose_SOURCE_DIR}"
    ${CMAKE_BINARY_DIR}
  )
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE
    USE_IPV6
    USE_WEBSOCKET
    USE_SERVER_STATS
)


if (WIN32)
  target_link_libraries(${PROJECT_NAME} PRIVATE     
    ${THREAD_LIBRARIES}
    OpenSSL::SSL 
    OpenSSL::Crypto
    OpenSSL::SSL OpenSSL::Crypto
    vscp-common
    ${SODIUM_LIBRARY}
  )
        
else()
  target_link_libraries(${PROJECT_NAME} PRIVATE     
    m
    dl
    ${THREAD_LIBRARIES}
    OpenSSL::SSL 
    OpenSSL::Crypto
    vscp-common
    ${SODIUM_LIBRARY}
  )
endif()

include(CTest)
if(BUILD_TESTING)
  add_executable(test-securememory test/test_securememory.cpp src/userlist.cpp)
  target_link_libraries(test-securememory PRIVATE vscp-common ${SODIUM_LIBRARY} ${THREAD_LIBRARIES})
  if(WIN32)
    target_link_libraries(test-securememory PRIVATE expat::expat ws2_32)
  else()
    target_link_libraries(test-securememory PRIVATE ${EXPAT_LIBRARIES})
  endif()
  add_test(NAME secure-password-memory COMMAND test-securememory "${CMAKE_CURRENT_SOURCE_DIR}/debug/users.json")
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
