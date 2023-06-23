cmake_minimum_required(VERSION 3.25)
project(GoDNS C)

set(CMAKE_C_STANDARD 11)

add_executable(GoDNS src/main.c include/dns_structure.h)