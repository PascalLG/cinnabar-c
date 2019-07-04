#=========================================================================

cmake_minimum_required(VERSION 3.11)
project(CnbrTest)

if(WIN32)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

#---------------------------------------------------------------
# Test application
#---------------------------------------------------------------

add_executable(${CMAKE_PROJECT_NAME} test.c)
if(NOT WIN32)
	target_compile_options(${CMAKE_PROJECT_NAME} PUBLIC -Wall)
	target_link_libraries(${CMAKE_PROJECT_NAME} m)
endif()

#=========================================================================
