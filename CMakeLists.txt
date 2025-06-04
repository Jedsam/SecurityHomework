cmake_minimum_required(VERSION 3.10)
project(securityproject CXX)
set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

set(EXECUTABLES server user authority)

set(sources_server)
set(sources_user)
set(sources_authority)

set(HELPING_FUNCTIONS connection.cpp)

foreach(executable ${EXECUTABLES})
    add_executable(${executable} ${executable}.cpp ${executable}.hpp ${sources_${executable}} ${HELPING_FUNCTIONS})
    target_include_directories(${executable} PRIVATE ${SODIUM_INCLUDE_DIRS})
    target_link_libraries(${executable} PRIVATE ${SODIUM_LIBRARIES})
endforeach()
