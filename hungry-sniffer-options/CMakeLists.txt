cmake_minimum_required(VERSION 2.8.12)

find_package(Qt5Widgets REQUIRED)

set(OPTIONS_SRC
  call.cpp
  resolve_hostname.cpp
  stats_length.cpp
  stats_endpoints.cpp
)

set(OPTIONS_HDR
  options.h
  stats_length.h
  stats_endpoints.h
)


if(UNIX)
  list(APPEND OPTIONS_SRC arpspoof.cpp portredirect.cpp)
  if(SDK_PATH)
    include_directories(../sdk)
    set(OPTIONS_LIBS hungry-sniffer-sdk)
  else()
    PKG_CHECK_MODULES(HS_SDK REQUIRED HungrySniffer)
    include_directories(${HS_SDK_INCLUDE_DIRS})
    set(OPTIONS_LIBS ${HS_SDK_LIBRARIES})
  endif()
endif()

if(WIN32)
  include_directories(../sdk)
  set(OPTIONS_LIBS ws2_32 hungry-sniffer-sdk)
endif()

if(CMAKE_COMPILER_IS_GNUCXX)
  add_compile_options(-fno-exceptions -fno-rtti)
  set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fno-exceptions -fno-rtti")
endif()

add_library(hungry-sniffer-options SHARED ${OPTIONS_SRC} ${OPTIONS_HDR})
target_compile_features(hungry-sniffer-options PRIVATE cxx_range_for)
target_link_libraries(hungry-sniffer-options ${OPTIONS_LIBS} Qt5::Widgets)
set_property(TARGET hungry-sniffer-options PROPERTY INTERPROCEDURAL_OPTIMIZATION True)

if(UNIX AND NOT APPLE)
  install(FILES $<TARGET_FILE:hungry-sniffer-options>
          DESTINATION share/hungry-sniffer/plugins/
          RENAME 50_options.so
  )
endif()

if(WIN32)
  install(FILES $<TARGET_FILE:hungry-sniffer-options>
          DESTINATION bin/plugins
          RENAME 50_options.so
  )
endif()
