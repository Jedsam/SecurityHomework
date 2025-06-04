cmake_minimum_required(VERSION 3.10)
project(securityproject CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

set(EXECUTABLES server user authority)

set(SOURCES_SERVER server.h)
set(SOURCES_USER user.h authority.h)
set(SOURCES_AUTHORITY authority.h)

set(HELPING_FUNCTIONS)

foreach(executable ${EXECUTABLES})
    add_executable(${executable} ${executable}.cpp ${SOURCES_${executable}} ${HELPING_FUNCTIONS})
    target_include_directories(${executable} PRIVATE ${SODIUM_INCLUDE_DIRS})
    target_link_libraries(${executable} PRIVATE ${SODIUM_LIBRARIES})
endforeach()
