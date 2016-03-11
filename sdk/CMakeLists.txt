cmake_minimum_required(VERSION 2.8.12)

set(SDK_SRC
    protocol.cpp
    globals.cpp
    transport_layer_packet.cpp
)

set(SDK_HDR
    hs_core.h
    hs_advanced_packets.h
    hs_prefs.h
    hs_protocol.h
    hs_plugin.h
    hs_stats.h
    hs_transport_layer_packet.h
)

if(CMAKE_COMPILER_IS_GNUCXX)
  add_compile_options(-fno-exceptions -fno-rtti)
  set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fno-exceptions -fno-rtti")
endif()

add_library(hungry-sniffer-sdk SHARED ${SDK_SRC} ${SDK_HDR})
target_compile_features(hungry-sniffer-sdk PRIVATE cxx_range_for)
target_compile_definitions(hungry-sniffer-sdk PRIVATE SDK_LIBRARY)
set_property(TARGET hungry-sniffer-sdk PROPERTY INTERPROCEDURAL_OPTIMIZATION True)

if(SDK_DOCS)
  find_package(Doxygen)
  if(DOXYGEN_FOUND)
    add_custom_target(doc ALL
      ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating API documentation with Doxygen" VERBATIM
    )
  endif(DOXYGEN_FOUND)
endif(SDK_DOCS)

if(UNIX AND NOT APPLE)
  install(TARGETS hungry-sniffer-sdk LIBRARY DESTINATION lib)

  # pkg-config file
  SET(PKG_CONFIG_LIBDIR "\${prefix}/lib")
  SET(PKG_CONFIG_INCLUDEDIR "\${prefix}/include/HungrySniffer")
  SET(PKG_CONFIG_LIBS "-lhungry-sniffer-sdk")
  SET(PKG_CONFIG_CFLAGS "-I\${includedir}")
  CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/pkg-config.pc.cmake"
                 "${CMAKE_CURRENT_BINARY_DIR}/HungrySniffer.pc")
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/HungrySniffer.pc"
          DESTINATION lib/pkgconfig/)

  if(INSTALL_SDK_HEADERS)
    install(FILES ${SDK_HDR} DESTINATION include/HungrySniffer)
  endif()

  if(SDK_DOCS AND DOXYGEN_FOUND)
    install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/html/" DESTINATION "share/doc/hungry-sniffer-${PROJECT_VERSION}")
  endif(SDK_DOCS AND DOXYGEN_FOUND)
endif()

if(WIN32)
  install(TARGETS hungry-sniffer-sdk LIBRARY DESTINATION bin)

  if(INSTALL_SDK_HEADERS)
    install(FILES ${SDK_HDR} DESTINATION "sdk/")
  endif(INSTALL_SDK_HEADERS)

  if(SDK_DOCS AND DOXYGEN_FOUND)
    install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/html/" DESTINATION "docs/")
  endif(SDK_DOCS AND DOXYGEN_FOUND)
endif()
