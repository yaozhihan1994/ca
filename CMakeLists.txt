cmake_minimum_required(VERSION 2.8)

project(server)

include_directories(${PROJECT_SOURCE_DIR}/include/ 
                    ${PROJECT_SOURCE_DIR}/include/asn/
                    ${PROJECT_SOURCE_DIR}/include/openssl/)

link_directories(${PROJECT_SOURCE_DIR}/lib/)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++0x")     

aux_source_directory(${PROJECT_SOURCE_DIR}/src/asn/ SRC_MY)

set(SOURCES_CPP ${SRC_MY} 
		  ${PROJECT_SOURCE_DIR}/src/CertMng.cpp 
		  ${PROJECT_SOURCE_DIR}/src/CertOp.cpp
                  ${PROJECT_SOURCE_DIR}/src/CRLMng.cpp
                  ${PROJECT_SOURCE_DIR}/src/Server.cpp
                  ${PROJECT_SOURCE_DIR}/src/Message.cpp)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/output/)
add_executable(server ${SOURCES_CPP})
target_link_libraries(server pthread ssl crypto)
