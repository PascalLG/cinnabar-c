#=========================================================================

cmake_minimum_required(VERSION 3.11)
project(rsa-sign)

if(WIN32)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

#---------------------------------------------------------------
# rsa-sign application
#---------------------------------------------------------------

add_executable(${CMAKE_PROJECT_NAME} rsa-sign.c ../cinnabar.h ../cinnabar.c)
if(NOT WIN32)
	target_compile_options(${CMAKE_PROJECT_NAME} PUBLIC -Wall)
endif()

#=========================================================================
