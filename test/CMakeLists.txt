project(test)

# Create the executable
add_executable(${PROJECT_NAME} test.c
                      ../third-party/vscp-firmware/common/vscp-firmware-helper.c
                      ../third-party/vscp-firmware/common/vscp-aes.c
                      ../third-party/vscp-firmware/common/crc.c)

include_directories(
  .
  ..
  ../third-party/vscp-firmware/common/
)

target_link_libraries(${PROJECT_NAME}
    m
)

# Link the static library from subproject1 using its alias sub::lib1
# Link the header only library from subproject2 using its alias sub::lib2
# This will cause the include directories for that target to be added to this project
#target_link_libraries(${PROJECT_NAME}
#    sub::lib1
#    sub::lib2
#)
