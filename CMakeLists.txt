#***************************************************************************
# Copyright:  Matthias Schmieder,
# E-Mail:     schmieder.matthias@gmail.com
# Year:       2016
#***************************************************************************
cmake_minimum_required(VERSION 2.8)


# Set a consistent MACOSX_RPATH default across all CMake versions. 
# When CMake 2.8.12 is required, change this default to 1.
# When CMake 3.0.0 is required, remove this block (see CMP0042).
if(NOT DEFINED CMAKE_MACOSX_RPATH)
  set(CMAKE_MACOSX_RPATH 0)
endif()

project("minizip")

# set cmake debug postfix to d
set(CMAKE_DEBUG_POSTFIX "d")

# Ensure correct version of zlib is referenced
set(ZLIB_ROOT ${DEF_ZLIB_ROOT} CACHE PATH "Parent directory of zlib installation")
find_package(ZLIB REQUIRED)
if(ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIRS})
endif()

set(MINIZIP_SRC "crypt.c"
  "ioapi.c"
  "ioapi_buf.c"
  "ioapi_mem.c"
  "unzip.c"
  "zip.c")

set(MINIZIP_PUBLIC_HEADERS "crypt.h"
  "ioapi.h"
  "ioapi_buf.h"
  "ioapi_mem.h"
  "unzip.h"
  "zip.h")

if(WIN32)
  list(APPEND MINIZIP_SRC "iowin32.c")
  list(APPEND MINIZIP_PUBLIC_HEADERS "iowin32.h")
  add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
endif()

if(UNIX)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -O3")
  add_definitions(-D__USE_FILE_OFFSET64)
  add_definitions(-D__USE_LARGEFILE64)
  add_definitions(-D_LARGEFILE64_SOURCE)
  add_definitions(-D_FILE_OFFSET_BIT=64)
endif()

if(CMAKE_C_COMPILER MATCHES ".*clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse3 -msse4.1 -maes")
endif()

# Configure AES support using OpenSSL
option(USE_AES "enables AES encryption using OpenSSL" ON)
if(USE_AES)
  # Find OpenSSL package
  find_package(OpenSSL REQUIRED)
  if(OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
  endif()

  # Add OpenSSL-based AES implementation
  list(APPEND MINIZIP_SRC "fileenc_openssl.c")
  list(APPEND MINIZIP_PUBLIC_HEADERS "fileenc_openssl.h")

  add_definitions(-DHAVE_AES)
endif()

# Configure Deflate64 support
option(USE_DEFLATE64 "enables Deflate64 decompression support" ON)
if(USE_DEFLATE64)
  # Add Deflate64 implementation files
  list(APPEND MINIZIP_SRC
    "deflate64/infback9.c"
    "deflate64/inftree9.c")
  list(APPEND MINIZIP_PUBLIC_HEADERS
    "deflate64/infback9.h"
    "deflate64/inflate9.h"
    "deflate64/inftree9.h"
    "deflate64/inffix9.h")

  add_definitions(-DHAVE_DEFLATE64)
endif()

# Configure BZIP2 support
option(USE_BZIP2 "enables BZIP2 compression support" ON)
if(USE_BZIP2)
  # Add BZIP2 implementation files
  list(APPEND MINIZIP_SRC
    "bzlib/blocksort.c"
    "bzlib/bzlib.c"
    "bzlib/compress.c"
    "bzlib/crctable.c"
    "bzlib/decompress.c"
    "bzlib/huffman.c"
    "bzlib/randtable.c")
  list(APPEND MINIZIP_PUBLIC_HEADERS
    "bzlib/bzlib.h"
    "bzlib/bzlib_private.h")

  add_definitions(-DHAVE_BZIP2)
endif()

# Configure LZMA support
# Note: LZMA support requires additional files from LZMA SDK (LzFind.c, etc.)
# These files are not included by default due to their size
option(USE_LZMA "enables LZMA compression support" OFF)
if(USE_LZMA)
  # Add LZMA implementation files
  list(APPEND MINIZIP_SRC
    "lzma/LzmaEnc.c"
    "lzma/LzmaDec.c")
  list(APPEND MINIZIP_PUBLIC_HEADERS
    "lzma/LzmaEnc.h"
    "lzma/LzmaDec.h"
    "lzma/7zTypes.h")

  add_definitions(-DHAVE_LZMA)
endif()

# create minizip library
add_library(minizip ${MINIZIP_SRC} ${MINIZIP_PUBLIC_HEADERS})
target_link_libraries(minizip ZLIB::ZLIB)

if(USE_AES)
  target_link_libraries(minizip ${OPENSSL_LIBRARIES})
endif()

install(TARGETS minizip EXPORT minizip-exports
  INCLUDES DESTINATION "include"
  RUNTIME DESTINATION "bin"
  LIBRARY DESTINATION "lib"
  ARCHIVE DESTINATION "lib")

set(INSTALL_CMAKE_DIR "cmake")
install(EXPORT minizip-exports
        DESTINATION "${INSTALL_CMAKE_DIR}"
        NAMESPACE "MINIZIP::")

# Create and install CMake package config version file to allow find_package()

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/minizip-config-version.cmake"
  VERSION 1.2
  COMPATIBILITY SameMajorVersion)

# Create config for find_package()

if(USE_AES)
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/minizip-config.cmake.in"
"
@PACKAGE_INIT@
include(CMakeFindDependencyMacro)
find_dependency(ZLIB)
find_dependency(OpenSSL)
include(\"\${CMAKE_CURRENT_LIST_DIR}/minizip-exports.cmake\")
check_required_components(minizip)
")
else()
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/minizip-config.cmake.in"
"
@PACKAGE_INIT@
include(CMakeFindDependencyMacro)
find_dependency(ZLIB)
include(\"\${CMAKE_CURRENT_LIST_DIR}/minizip-exports.cmake\")
check_required_components(minizip)
")
endif()

configure_package_config_file(
  "${CMAKE_CURRENT_BINARY_DIR}/minizip-config.cmake.in"
  minizip-config.cmake
  INSTALL_DESTINATION "${INSTALL_CMAKE_DIR}"
  NO_SET_AND_CHECK_MACRO)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/minizip-config-version.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/minizip-config.cmake"
        DESTINATION "${INSTALL_CMAKE_DIR}")

install(FILES ${MINIZIP_PUBLIC_HEADERS}
  DESTINATION "include/minizip")

option (BUILD_TEST "enabled building of executables minizip and miniunz. Requires ZLIB!" OFF)
if(BUILD_TEST)
  add_executable(miniunz_exec miniunz.c minishared.c)
  target_link_libraries(miniunz_exec minizip)

  add_executable(minizip_exec minizip.c minishared.c)
  target_link_libraries(minizip_exec minizip)

  install(TARGETS miniunz_exec minizip_exec
          RUNTIME DESTINATION "bin")
endif()

