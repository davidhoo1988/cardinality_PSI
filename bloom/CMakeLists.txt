cmake_minimum_required(VERSION 3.16)
project(BF)

set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR}/install)
set(DEBUG ON)

## include header files
include_directories(${PROJECT_SOURCE_DIR}/)

## include source files
set(BF_SOURCES bloom_filter_example01.cpp)
set(BF_PSI_SOURCES bloom_filter_for_PSI.cpp) 

if (DEBUG)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fopenmp")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -fopenmp")
endif ()


add_executable(bloom_filter_example01 ${BF_SOURCES})
add_executable(bloom_filter_for_PSI ${BF_PSI_SOURCES})