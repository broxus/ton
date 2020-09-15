cmake_minimum_required(VERSION 3.0.2 FATAL_ERROR)

set(FTABI_SOURCE
  ftabi/Abi.cpp
  ftabi/Abi.hpp)

add_library(ftabi STATIC ${FTABI_SOURCE})

target_include_directories(ftabi PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..
)

target_compile_features(ftabi PRIVATE cxx_std_17)

target_link_libraries(ftabi PUBLIC ton_crypto ton_block smc-envelope)
