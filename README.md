requirements
- openssl
- curl
- nlohmann/json

The header file, which is found in 
`include/tsar/tsar.hpp`
requires the nlohmann/json header to be in your include path of the project.

The src/main.cpp file is made for testing the library.

to build
```
mkdir build && cd build
cmake ..
make
```
