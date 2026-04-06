cmake_minimum_required(VERSION 3.16)
project(libx86d C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

set(LIB_SOURCES
    src/core/core.c
    src/core/decode.c
    src/core/opcodes.c
)

add_library(x86d_static STATIC ${LIB_SOURCES})
target_include_directories(x86d_static
    PUBLIC  include
    PRIVATE src
)
set_target_properties(x86d_static PROPERTIES OUTPUT_NAME x86d)

add_executable(x86d src/cli/main.c)
target_link_libraries(x86d PRIVATE x86d_static)

install(TARGETS x86d_static DESTINATION lib)
install(FILES include/libx86d.h DESTINATION include)
install(TARGETS x86d DESTINATION bin)

file(GLOB TEST_ASM_FILES ${CMAKE_SOURCE_DIR}/tests/*.asm)

foreach(test_file ${TEST_ASM_FILES})
    get_filename_component(test_name ${test_file} NAME_WE)

    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/${test_name}.bin
        COMMAND nasm -f bin ${test_file} -o ${CMAKE_BINARY_DIR}/${test_name}.bin
        DEPENDS ${test_file}
        COMMENT "Assembling ${test_name}.asm"
    )

    add_custom_target(${test_name}_bin ALL
        DEPENDS ${CMAKE_BINARY_DIR}/${test_name}.bin
    )
endforeach()