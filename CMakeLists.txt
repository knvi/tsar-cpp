cmake_minimum_required(VERSION 3.13)
project(TSAR_CPP CXX)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the directory with header files
include_directories(include)

# Add all the .cpp files in the src directory to the executable
file(GLOB SOURCES "src/*.cpp")
add_executable(TSAR_CPP ${SOURCES})

find_package(CURL REQUIRED)
target_link_libraries(TSAR_CPP CURL::libcurl)

# openssl
find_package(OpenSSL REQUIRED)
target_link_libraries(TSAR_CPP OpenSSL::SSL OpenSSL::Crypto)

# -D_FORTIFY_SOURCE=2
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_FORTIFY_SOURCE=2 -fstack-protector -Wall")

# -fsanitize=cfi
