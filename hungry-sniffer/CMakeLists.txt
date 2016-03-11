cmake_minimum_required(VERSION 2.8.12)

find_package(Qt5Widgets REQUIRED)
set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories(../sdk ../)

set(HS_SRC
    about.cpp
    about_plugins.cpp
    data_structure.cpp
    devicechoose.cpp
    EthernetPacket.cpp
    filter_tree.cpp
    main.cpp
    optionsdisabler.cpp
    packetstable_model.cpp
    packetstats.cpp
    preferences.cpp
    sniff_window.cpp
    sniff_window_files.cpp
    sniff_window_packetsFlow.cpp
    sniff_window_python.cpp
    statusbar.cpp

    prefs/general_modules.cpp
    prefs/general_ui.cpp
    prefs/hidden_interfaces.cpp
    prefs/pref_add.cpp

    widgets/history_line_edit.cpp
    widgets/interface_selector.cpp
    widgets/string_list_selector.cpp

    ../QHexEdit/qhexedit_p.cpp
    ../QHexEdit/xbytearray.cpp
    ../QHexEdit/qhexedit.cpp
    ../QHexEdit/commands.cpp
)

set(HS_HDR
    about.h
    about_plugins.h
    devicechoose.h
    EthernetPacket.h
    filter_tree.h
    optionsdisabler.h
    packetstable_model.h
    packetstats.h
    preferences.h
    sniff_window.h
    statusbar.h
    ThreadQueue.h

    prefs/general_modules.h
    prefs/general_ui.h
    prefs/hidden_interfaces.h

    widgets/history_line_edit.h
    widgets/interface_selector.h
    widgets/string_list_selector.h

    ../QHexEdit/qhexedit.h
    ../QHexEdit/commands.h
    ../QHexEdit/qhexedit_p.h
    ../QHexEdit/xbytearray.h
)

set(HS_FORMS sniff_window.ui)

set(HS_RESOURCES icons/icons.qrc)

qt5_wrap_ui(HS_FORMS_HDR ${HS_FORMS})
qt5_add_resources(HS_RESOURCES_RCC ${HS_RESOURCES})

add_definitions(-DAPP_VERSION="${PROJECT_VERSION}")
set(OPTIONS_LIBS hungry-sniffer-sdk)
if(UNIX)
  set(HS_LIBS dl pcap pthread)
endif(UNIX)

if(WIN32)
  set(HS_LIBS ws2_32 wpcap)
endif(WIN32)

if(ENABLE_PYTHON)
  list(APPEND HS_SRC python_thread.cpp)
  list(APPEND HS_HDR python_thread.h)
  add_definitions(-DPYTHON_CMD)
  FIND_PACKAGE(PythonInterp REQUIRED)
  FIND_PACKAGE(PythonLibs ${PYTHON_VERSION_STRING} REQUIRED)
  include_directories(${PYTHON_INCLUDE_DIRS})
  list(APPEND HS_LIBS ${PYTHON_LIBRARIES})
endif()

if(CMAKE_COMPILER_IS_GNUCXX)
  add_compile_options(-fno-rtti)
  set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} -fno-rtti")
endif()

add_executable(hungry-sniffer ${HS_SRC} ${HS_HDR} ${HS_FORMS_HDR} ${HS_RESOURCES_RCC})
target_compile_features(hungry-sniffer PRIVATE cxx_range_for)
target_link_libraries(hungry-sniffer ${HS_LIBS} Qt5::Widgets hungry-sniffer-sdk)
set_property(TARGET hungry-sniffer PROPERTY INTERPROCEDURAL_OPTIMIZATION 1)

install(TARGETS hungry-sniffer
        RUNTIME DESTINATION bin)

if(UNIX AND NOT APPLE)
  install(FILES hungry-sniffer.desktop
          DESTINATION share/applications/)
endif()

if(WIN32)
  set(QT5_BIN_PATH ${QT5_PATH}/bin)
  install(FILES
             ${QT5_BIN_PATH}/Qt5Core.dll
             ${QT5_BIN_PATH}/Qt5Gui.dll
             ${QT5_BIN_PATH}/Qt5Widgets.dll
          DESTINATION bin)
endif()
