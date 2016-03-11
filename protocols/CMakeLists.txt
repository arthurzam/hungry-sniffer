cmake_minimum_required(VERSION 2.8.12)

set(PROTOCOLS_SRC
    ArpPacket.cpp
    DNSPacket.cpp
    ICMPPacket.cpp
    IPPacket.cpp
    IPv6Packet.cpp
    TCPPacket.cpp
    VRRPPacket.cpp
    call.cpp
    HTTPPacket.cpp
    ICMPv6Packet.cpp
    UDPPacket.cpp
)

set(PROTOCOLS_HDR
    ArpPacket.h
    HTTPPacket.h
    ICMPv6Packet.h
    UDPPacket.h
    DNSPacket.h
    ICMPPacket.h
    IPPacket.h
    IPv6Packet.h
    TCPPacket.h
    VRRPPacket.h
)

if(UNIX)
  add_definitions(-DQ_OS_UNIX)

  if(SDK_PATH)
    INCLUDE_DIRECTORIES(../sdk)
    list(APPEND PROTOCOLS_LIBS hungry-sniffer-sdk)
  else()
    PKG_CHECK_MODULES(HS_SDK REQUIRED HungrySniffer)
    INCLUDE_DIRECTORIES(${HS_SDK_INCLUDE_DIRS})
    list(APPEND PROTOCOLS_LIBS ${HS_SDK_LIBRARIES})
  endif()
endif()

if(WIN32)
  INCLUDE_DIRECTORIES(../sdk)
  set(PROTOCOLS_LIBS ws2_32 hungry-sniffer-sdk)
  add_definitions(-DQ_OS_WIN32)
endif()

if(CMAKE_COMPILER_IS_GNUCXX)
  add_compile_options(-fno-exceptions -fno-rtti)
  set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fno-exceptions -fno-rtti")
endif()

if(MINGW)
  add_definitions(-DQ_CC_MINGW)
endif()

add_library(hungry-sniffer-protocols SHARED ${PROTOCOLS_SRC} ${PROTOCOLS_HDR})
target_compile_features(hungry-sniffer-protocols PRIVATE cxx_range_for)
target_link_libraries(hungry-sniffer-protocols ${PROTOCOLS_LIBS})
set_property(TARGET hungry-sniffer-protocols PROPERTY INTERPROCEDURAL_OPTIMIZATION True)

if(UNIX AND NOT APPLE)
  install(FILES $<TARGET_FILE:hungry-sniffer-protocols>
          DESTINATION share/hungry-sniffer/plugins/
          RENAME 01_base.so
  )
endif()

if(WIN32)
  install(FILES $<TARGET_FILE:hungry-sniffer-protocols>
          DESTINATION bin/plugins
          RENAME 01_base.dll
  )
endif()
