cmake_minimum_required(VERSION 3.10)
project(TbTool C)

# -------------------------------------------------------
# Build Options
# -------------------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(TARGET_NAME tb_tool)

# -------------------------------------------------------
# Include / Source Directories
# -------------------------------------------------------
include_directories(
    ${PROJECT_SOURCE_DIR}/inc
    ${PROJECT_SOURCE_DIR}/3rdparty/include
)

file(GLOB SRC_FILES
    "${PROJECT_SOURCE_DIR}/src/*.c"
)

# -------------------------------------------------------
# Create Executable
# -------------------------------------------------------
add_executable(${TARGET_NAME} ${SRC_FILES})

# -------------------------------------------------------
# Link External Libraries
# -------------------------------------------------------
# 예: libmylib.a 를 3rdparty/lib 에 넣었을 경우
link_directories(${PROJECT_SOURCE_DIR}/3rdparty/lib)
# target_link_libraries(${TARGET_NAME} mylib)

# -------------------------------------------------------
# Build Output Directory
# -------------------------------------------------------
set_target_properties(${TARGET_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/build
)

