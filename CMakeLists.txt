cmake_minimum_required(VERSION 3.16)
project(raw_socket)

set(CMAKE_CXX_STANDARD 14)

add_executable(raw_socket main.cpp net.cpp net.h ethernet.cpp ethernet.h arp.cpp arp.h ip.cpp ip.h utils.cpp utils.h icmp.cpp icmp.h my_buf.cpp my_buf.h binary_trie.h config.cpp config.h napt.cpp napt.h)
