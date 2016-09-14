cmake_minimum_required(VERSION 2.8)
project(freeradius-snmp C)

if (CMAKE_BINARY_DIR STREQUAL ${CMAKE_SOURCE_DIR})
    message(FATAL_ERROR "Building in source dir prohibited. Remove CMakeCache.txt and try 'mkdir build && cd build && cmake ..'.")
endif ()

if (NOT CMAKE_BUILD_TYPE OR CMAKE_BUILD_TYPE EQUAL "")
    message(STATUS "No build type selected, default to RelWithDebInfo")
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif ()

SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/cmake/modules)

find_package(Libnetsnmp REQUIRED)

#find_package(Libfreeradius3 REQUIRED)

set(LIBFREERADIUS_INCLUDE_DIRS "../../")
set(INCLUDES ${LIBFREERADIUS_INCLUDE_DIRS} ${LIBNETSNMP_INCLUDE_DIRS})

set(LIBS ${LIBFREERADIUS_LIBRARIES} ${LIBNETSNMP_LIBRARIES})

set(SOURCES rlm_snmp.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -include ${CMAKE_SOURCE_DIR}/../../freeradius-devel/build.h")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Wextra -Werror -Wno-unused-function")
add_definitions(-DGNU_SOURCE -DFORTIFY_SOURCE=2 -DSTANDALONE_BUILD=1)

include_directories(${INCLUDES})

add_library(rlm_snmp SHARED ${SOURCES})
set_target_properties(rlm_snmp PROPERTIES PREFIX "")
target_link_libraries(rlm_snmp ${LIBS})

install(TARGETS rlm_snmp LIBRARY DESTINATION lib)
