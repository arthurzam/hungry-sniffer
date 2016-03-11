cmake_minimum_required(VERSION 2.8.12)

OPTION(ENABLE_PYTHON "Enable Python interpreter with the UI" ON)
OPTION(INSTALL_SDK_HEADERS "Install also the SDK headers - used for plugins development" ON)
OPTION(SDK_DOCS "create the docs with doxygen and install them" OFF)

set(PROJECT_VERSION "1.2")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

set(SDK_PATH sdk)
link_directories(${CMAKE_BINARY_DIR}/sdk)

if(WIN32)
  add_definitions(-DWIN32)
endif()

if(MINGW)
  add_compile_options(-static-libgcc -static-libstdc++ -static)
endif()

set(CMAKE_SKIP_RPATH TRUE)

add_subdirectory(sdk)
add_subdirectory(protocols)
add_subdirectory(hungry-sniffer-options)
add_subdirectory(hungry-sniffer)
