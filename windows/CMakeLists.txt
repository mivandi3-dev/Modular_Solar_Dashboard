cmake_minimum_required(VERSION 3.24)
project(SolarniMonitor2 VERSION 4.0.0 LANGUAGES C CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} --codepage=65001")  # app.rc je UTF-8 (izdavač: Marko Ivandić)

# ---------------------------------------------------------------- vanjske biblioteke (third_party/fetch.ps1)
add_library(sqlite3 STATIC third_party/sqlite/sqlite3.c)
target_include_directories(sqlite3 PUBLIC third_party/sqlite)
target_compile_definitions(sqlite3 PRIVATE SQLITE_DQS=0 SQLITE_THREADSAFE=1 SQLITE_DEFAULT_WAL_SYNCHRONOUS=1
                                           SQLITE_OMIT_LOAD_EXTENSION)

# ---------------------------------------------------------------- jezgra (bez GUI-ja – koriste je i testovi)
add_library(solari_core STATIC
    src/util.cpp src/config.cpp src/layout.cpp src/modbus.cpp src/storage.cpp src/data.cpp
    src/weather.cpp src/net.cpp src/poller.cpp src/system.cpp src/images.cpp src/i18n.cpp
    src/secret.cpp src/alerts.cpp src/report.cpp src/remote.cpp src/dashboard.cpp src/cloud.cpp src/api.cpp
    src/service.cpp src/smartlogger_export.cpp src/sunspec.cpp src/fronius.cpp src/vendors.cpp
    src/crypto.cpp src/users.cpp src/mailer.cpp src/tls.cpp src/totp.cpp src/serial.cpp src/offgrid.cpp src/webguard.cpp
    src/ipc.cpp src/broker.cpp src/api_ipc.cpp)
target_include_directories(solari_core PUBLIC src third_party third_party/webview2/include)
target_compile_definitions(solari_core PUBLIC UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
                                              SOLARI_VERSION="${PROJECT_VERSION}")
target_link_libraries(solari_core PUBLIC sqlite3 ws2_32 iphlpapi bcrypt ncrypt secur32 crypt32 setupapi hid winhttp windowscodecs ole32 oleaut32 uuid shell32
                                         shlwapi advapi32 user32 gdi32 shcore dwmapi)
# 4.0 (W8): gradnja s AddressSanitizerom i UndefinedBehaviorSanitizerom samo za testove i fuzz (zasebna mapa gradnje);
# ASan na mingw traži dinamičku izvršnu biblioteku, pa se tada ne povezuje statički i ne uključuje CFG
option(SOLARI_SANITIZE "ASan + UBSan (samo testovi/fuzz, nikad izdanje)" OFF)
if(SOLARI_SANITIZE)
    target_compile_options(solari_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
    target_link_options(solari_core PUBLIC -fsanitize=address,undefined)
    set(SOLARI_STATIC "")
else()
    set(SOLARI_STATIC -static)
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(solari_core PUBLIC -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
                                              -Wno-unknown-pragmas)
    # 4.0 (SMA-22): zaštita stoga i Control Flow Guard (uz ASLR/DEP koje llvm-mingw već uključuje)
    target_compile_options(solari_core PUBLIC -fstack-protector-strong)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND NOT SOLARI_SANITIZE)
        target_compile_options(solari_core PUBLIC -mguard=cf)
        target_link_options(solari_core PUBLIC -mguard=cf -Wl,--guard-cf)
    endif()
endif()

# ---------------------------------------------------------------- aplikacija
add_executable(SolarniMonitor WIN32 src/main.cpp src/app.cpp src/webview.cpp src/bridge.cpp res/app.rc)
target_link_libraries(SolarniMonitor PRIVATE solari_core)
target_link_options(SolarniMonitor PRIVATE -static -municode)

# Web sučelje, zadane slike i WebView2Loader.dll idu pokraj .exe (sinkronizira se pri svakoj izgradnji)
add_custom_target(runtime_files ALL
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/web ${CMAKE_BINARY_DIR}/web
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/assets ${CMAKE_BINARY_DIR}/assets
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/third_party/webview2/x64/WebView2Loader.dll
            ${CMAKE_BINARY_DIR}/WebView2Loader.dll
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_SOURCE_DIR}/third_party/curl ${CMAKE_BINARY_DIR}/curl
    COMMENT "Kopiram web sučelje i slike")
add_dependencies(SolarniMonitor runtime_files)

# ---------------------------------------------------------------- Solarni poslužitelj (logger → API za klijente)
add_executable(SolarniServer WIN32 src/server_main.cpp src/app.cpp src/webview.cpp src/bridge.cpp res/server.rc)
# Samo za automatske testove u zasebnoj mapi (cmake -B build-dev -DSOLARI_DEV_NO_UAC=ON); build.ps1 i Setup je nikad ne uključuju
option(SOLARI_DEV_NO_UAC "Solarni poslužitelj bez zahtjeva za administratorskim pravima (samo razvoj)" OFF)
if(SOLARI_DEV_NO_UAC)
    set_source_files_properties(res/server.rc PROPERTIES COMPILE_DEFINITIONS SOLARI_DEV_NO_UAC)
    # 4.0 (B1): razvojna gradnja smije uzeti SID gatewaya i ime kanala iz okoline (SOLARI_DEV_GATEWAY_SID/_API_PIPE)
    target_compile_definitions(solari_core PUBLIC SOLARI_DEV_BUILD)
endif()
target_link_libraries(SolarniServer PRIVATE solari_core)
target_link_options(SolarniServer PRIVATE -static -municode)
add_dependencies(SolarniServer runtime_files)

# ---------------------------------------------------------------- testovi (doctest)
enable_testing()
add_executable(solari_tests tests/test_main.cpp tests/test_security.cpp tests/test_b1.cpp tests/test_devices_s2.cpp tests/test_mailer.cpp)
target_link_libraries(solari_tests PRIVATE solari_core)
target_link_options(solari_tests PRIVATE ${SOLARI_STATIC})
add_dependencies(solari_tests runtime_files)  # testovi trebaju web\ i curl\ pokraj .exe
target_compile_definitions(solari_tests PRIVATE SOLARI_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME solari_tests COMMAND solari_tests)

# ---------------------------------------------------------------- fuzz (WT-15, AC-SRV-7): solari_fuzz [iteracije] [sjeme] [meta]
add_executable(solari_fuzz tests/fuzz_main.cpp)
target_link_libraries(solari_fuzz PRIVATE solari_core)
target_link_options(solari_fuzz PRIVATE ${SOLARI_STATIC})
