cmake_minimum_required(VERSION 3.0.2 FATAL_ERROR)

set(FTABI_SOURCE
  ftabi/Abi.cpp
  ftabi/Abi.hpp
  ftabi/Mnemonic.cpp
  ftabi/Mnemonic.hpp
  ftabi/utils.cpp
  ftabi/utils.hpp)

add_library(ftabi STATIC ${FTABI_SOURCE})

target_include_directories(ftabi PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/..
)

if (TONLIB_ENABLE_JNI AND NOT ANDROID) # jni is available by default on Android
  if (NOT JNI_FOUND)
    find_package(JNI REQUIRED)
  endif()
  message(STATUS "Found JNI: ${JNI_INCLUDE_DIRS} ${JNI_LIBRARIES}")
  target_include_directories(ftabi PUBLIC ${JAVA_INCLUDE_PATH} ${JAVA_INCLUDE_PATH2})
  target_link_libraries(ftabi PUBLIC ${JAVA_JVM_LIBRARY})
endif()

target_compile_features(ftabi PRIVATE cxx_std_17)

target_link_libraries(ftabi PUBLIC ton_crypto ton_block smc-envelope)
