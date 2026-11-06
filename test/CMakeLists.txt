cmake_minimum_required(VERSION 3.10)
project(websocket-test-clients LANGUAGES C)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(test-mongoose STATIC mongoose.c)
target_include_directories(test-mongoose PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(test-mongoose PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
if(WIN32)
  target_link_libraries(test-mongoose PUBLIC ws2_32)
endif()

foreach(PROTOCOL ws1 ws2)
  add_executable(test_${PROTOCOL} test_${PROTOCOL}.c)
  target_compile_features(test_${PROTOCOL} PRIVATE c_std_99)
  target_link_libraries(test_${PROTOCOL} PRIVATE test-mongoose OpenSSL::Crypto)
endforeach()
