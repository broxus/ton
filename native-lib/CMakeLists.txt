cmake_minimum_required(VERSION 3.4.1 FATAL_ERROR)

add_library(native-lib SHARED native-lib.cpp)

list(APPEND CMAKE_FIND_ROOT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/third_party/crypto/${ANDROID_ARCH_NAME}")
target_link_libraries(native-lib tonlibjson_static)
target_link_libraries(native-lib tonlib)
target_compile_options(native-lib PRIVATE
  -std=c++17
  -Wall
  -Wextra
  -Wno-unused-parameter
  -Wno-deprecated-declarations
  -Wconversion
  -Wno-sign-conversion
  -fno-omit-frame-pointer
  -ffunction-sections
  -fdata-sections
  -Wl,--gc-sections
  -Wl,--exclude-libs,ALL
)

#target_sources(native-lib PRIVATE ${ALL_TEST_SOURCE})
#target_link_libraries(native-lib all_tests)

set(TONLIB_API_JAVA_PACKAGE "com/broxus/ton")
target_compile_definitions(native-lib PRIVATE PACKAGE_NAME="${TONLIB_API_JAVA_PACKAGE}")

add_custom_command(TARGET native-lib POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E rename $<TARGET_FILE:native-lib> $<TARGET_FILE:native-lib>.debug
        COMMAND ${CMAKE_STRIP} --strip-debug --strip-unneeded $<TARGET_FILE:native-lib>.debug -o $<TARGET_FILE:native-lib>)

if (NOT CMAKE_CROSSCOMPILING)
  set(TONLIB_API_JAVA_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/)
  file(MAKE_DIRECTORY ${TONLIB_API_JAVA_PATH}${TONLIB_API_JAVA_PACKAGE})
  set(TONLIB_API_TLO_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../tl/generate/scheme/tonlib_api.tlo)
  set(TONLIB_API_TL_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../tl/generate/scheme/tonlib_api.tl)
  set(JAVADOC_TL_DOCUMENTATION_GENERATOR_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../tl/generate/JavadocTlDocumentationGenerator.php)
  set(GENERATE_JAVA_CMD tonlib_generate_java_api TonApi ${TONLIB_API_TLO_PATH} ${TONLIB_API_JAVA_PATH} ${TONLIB_API_JAVA_PACKAGE})
  if (PHP_EXECUTABLE)
    set(GENERATE_JAVA_CMD ${GENERATE_JAVA_CMD} && ${PHP_EXECUTABLE} ${JAVADOC_TL_DOCUMENTATION_GENERATOR_PATH}
            ${TONLIB_API_TL_PATH} ${TONLIB_API_JAVA_PATH}/${TONLIB_API_JAVA_PACKAGE}/TonApi.java androidx.annotation.Nullable @Nullable)
  endif()

  add_custom_target(tl_generate_java
          COMMAND ${GENERATE_JAVA_CMD}
          COMMENT "Generate java tl source files"
          DEPENDS tonlib_generate_java_api ${TONLIB_API_TLO_PATH}
          )
  add_dependencies(prepare_cross_compiling tl_generate_java)
endif()
