cmake_minimum_required(VERSION 3.16)
project(WebPanelVPNs)

set(CMAKE_CXX_STANDARD 23)

add_executable(WebPanelVPNs main.cpp)

find_package(Crow REQUIRED)
find_package(OpenSSL REQUIRED)

find_library(SQLITE3_LIB sqlite3 REQUIRED)

target_link_libraries(WebPanelVPNs PUBLIC
    Crow::Crow
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SQLITE3_LIB}
)

add_custom_command(TARGET WebPanelVPNs POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/templates
        $<TARGET_FILE_DIR:WebPanelVPNs>/templates
)
