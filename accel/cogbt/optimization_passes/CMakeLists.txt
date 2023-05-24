cmake_minimum_required(VERSION 3.13)

set(LLVM_HOME /home/loongson/llvm_install_cross)
set(CMAKE_C_COMPILER ${LLVM_HOME}/bin/clang)
set(CMAKE_CXX_COMPILER ${LLVM_HOME}/bin/clang++)
SET(CMAKE_CXX_FLAGS "-Wall -fno-rtti")
# generate compile_commands.json
# set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(OptimizationPasses)

# LLVM_DIR should contain file 'LLVMConfig.cmake'
set(LLVM_DIR ${LLVM_HOME}/lib/cmake/llvm)
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_DIR}")
message(STATUS "LLVM_INCLUDE_DIRS is ${LLVM_INCLUDE_DIRS}")
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})
include_directories(${LLVM_INCLUDE_DIRS})
link_directories(${LLVM_LIBRARY_DIRS})


# Add the list of subdirectories
set(SUB_DIRS flag-reduction
			 andi-reduction
			 sext-reduction
			 pattern)
set(OUTPUT_LIBRARY LLVMCustomReduction)

# Enter each subdirectory and build
foreach(subdir ${SUB_DIRS})
	add_subdirectory(${subdir})

	list(APPEND OBJ_LIBRARIES $<TARGET_OBJECTS:${subdir}>)
endforeach()

# generate the final shared library
add_library(${OUTPUT_LIBRARY} SHARED ${OBJ_LIBRARIES})
