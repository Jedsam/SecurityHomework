cmake_minimum_required(VERSION 3.10)
project(securityproject CXX)
set(CMAKE_CXX_STANDARD 20)
add_executable(server.o server.cpp)
add_executable(user.o user.cpp)

