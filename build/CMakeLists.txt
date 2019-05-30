cmake_minimum_required(VERSION 2.8)

project(server)

include_directories(../include/ 
                    ../include/asn/
                    ../include/openssl/)

link_directories(../lib/)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++0x")     

aux_source_directory(../src/asn/ SRC_MY)

set(SOURCES_CPP ${SRC_MY} 
		  ../src/CertMng.cpp 
		  ../src/CertOp.cpp
                  ../src/CRLMng.cpp
                  ../src/Server.cpp
                  ../src/Message.cpp)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../output/)
add_executable(server ${SOURCES_CPP})
target_link_libraries(server pthread ssl crypto)
