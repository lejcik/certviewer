cmake_minimum_required(VERSION 3.11 FATAL_ERROR)

project(certdump LANGUAGES CXX)

find_package(OpenSSL 3.0 REQUIRED)
find_package(GTest REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# unit-test executable

add_executable(certdump-test "")

target_include_directories(certdump-test
    PRIVATE
        ".")

target_sources(certdump-test
    PRIVATE
        certdump-test.cpp
        precomp.h
        precomp.cpp
        utils.h
        utils.cpp
        pem-tests.cpp
        der-tests.cpp
        ../certdump.h
        ../certdump.cpp
        ../openssl_helpers.h
        ../openssl_helpers.cpp)

target_link_libraries(certdump-test
    PRIVATE
        GTest::gtest
        OpenSSL::SSL)

# run the tests

enable_testing()

add_test(
    NAME certdump-test
    COMMAND $<TARGET_FILE:certdump-test>)
