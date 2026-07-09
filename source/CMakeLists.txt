set(BPF_SRC  ${CMAKE_CURRENT_SOURCE_DIR}/lunar.bpf.c)
set(BPF_OBJ  ${CMAKE_CURRENT_BINARY_DIR}/lunar.bpf.o)
set(BPF_SKEL ${CMAKE_CURRENT_BINARY_DIR}/lunar.skel.h)

add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG_EXECUTABLE}
        -target bpf -g -O2 -mcpu=v3 -D__TARGET_ARCH_${BPF_TARGET_ARCH}
        -I${SCX_INCLUDE}
        -I${CMAKE_CURRENT_SOURCE_DIR}
        -I${CMAKE_SOURCE_DIR}
        ${LIBBPF_CFLAGS_OTHER}
        -c ${BPF_SRC} -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling BPF scheduler"
    VERBATIM
)

set(lunarSource
    main.cpp
)

set(lunarHeader
    datatypes.h
    defines.h
    dispatches.h
    helpers.h
    lunar_topology.h
    mode_parsing.h
)
add_custom_command(
    OUTPUT ${BPF_SKEL}
    COMMAND sh -c "${BPFTOOL_EXECUTABLE} gen skeleton ${BPF_OBJ} > ${BPF_SKEL}"
    DEPENDS ${BPF_OBJ}
    COMMENT "Generating BPF skeleton"
    VERBATIM
)

add_custom_target(lunar_bpf DEPENDS ${BPF_OBJ} ${BPF_SKEL})

set_target_properties(lunar_bpf PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable(lunar
    ${lunarSource}
    ${lunarHeader}

)
add_dependencies(lunar lunar_bpf)

target_include_directories(lunar PRIVATE
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}
    ${LIBBPF_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/scx
)

target_link_libraries(lunar PRIVATE ${LIBBPF_LIBRARIES})

target_compile_options(lunar PRIVATE
    -Wall -Wextra -Wpedantic -fno-strict-aliasing -fwrapv
)


set_target_properties(lunar PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})


source_group(SourceFiles FILES ${lunarSource})
source_group(HeaderFiles FILES ${lunarHeader})

install(TARGETS lunar RUNTIME DESTINATION bin)
