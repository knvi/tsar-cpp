requirements
- openssl
- curl
- nlohmann/json

The header file, which is found in 
`include/tsar/tsar.hpp`
requires the nlohmann/json header to be in your include path of the project.

The src/main.cpp file is made for testing the library.

To use the client, put `include/tsar/tsar.hpp` (and the nlohmann/json header if you didn't yet) file into your include path.

to build (the tests)
```
mkdir build && cd build
cmake ..
make
```
