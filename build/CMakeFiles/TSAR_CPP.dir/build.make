# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /root/code/tsar-cpp

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /root/code/tsar-cpp/build

# Include any dependencies generated for this target.
include CMakeFiles/TSAR_CPP.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/TSAR_CPP.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/TSAR_CPP.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/TSAR_CPP.dir/flags.make

CMakeFiles/TSAR_CPP.dir/src/main.cpp.o: CMakeFiles/TSAR_CPP.dir/flags.make
CMakeFiles/TSAR_CPP.dir/src/main.cpp.o: ../src/main.cpp
CMakeFiles/TSAR_CPP.dir/src/main.cpp.o: CMakeFiles/TSAR_CPP.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/root/code/tsar-cpp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/TSAR_CPP.dir/src/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/TSAR_CPP.dir/src/main.cpp.o -MF CMakeFiles/TSAR_CPP.dir/src/main.cpp.o.d -o CMakeFiles/TSAR_CPP.dir/src/main.cpp.o -c /root/code/tsar-cpp/src/main.cpp

CMakeFiles/TSAR_CPP.dir/src/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/TSAR_CPP.dir/src/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /root/code/tsar-cpp/src/main.cpp > CMakeFiles/TSAR_CPP.dir/src/main.cpp.i

CMakeFiles/TSAR_CPP.dir/src/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/TSAR_CPP.dir/src/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /root/code/tsar-cpp/src/main.cpp -o CMakeFiles/TSAR_CPP.dir/src/main.cpp.s

# Object files for target TSAR_CPP
TSAR_CPP_OBJECTS = \
"CMakeFiles/TSAR_CPP.dir/src/main.cpp.o"

# External object files for target TSAR_CPP
TSAR_CPP_EXTERNAL_OBJECTS =

TSAR_CPP: CMakeFiles/TSAR_CPP.dir/src/main.cpp.o
TSAR_CPP: CMakeFiles/TSAR_CPP.dir/build.make
TSAR_CPP: /usr/lib/x86_64-linux-gnu/libcurl.so
TSAR_CPP: /usr/lib/x86_64-linux-gnu/libssl.so
TSAR_CPP: /usr/lib/x86_64-linux-gnu/libcrypto.so
TSAR_CPP: CMakeFiles/TSAR_CPP.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/root/code/tsar-cpp/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable TSAR_CPP"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/TSAR_CPP.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/TSAR_CPP.dir/build: TSAR_CPP
.PHONY : CMakeFiles/TSAR_CPP.dir/build

CMakeFiles/TSAR_CPP.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/TSAR_CPP.dir/cmake_clean.cmake
.PHONY : CMakeFiles/TSAR_CPP.dir/clean

CMakeFiles/TSAR_CPP.dir/depend:
	cd /root/code/tsar-cpp/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /root/code/tsar-cpp /root/code/tsar-cpp /root/code/tsar-cpp/build /root/code/tsar-cpp/build /root/code/tsar-cpp/build/CMakeFiles/TSAR_CPP.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/TSAR_CPP.dir/depend

