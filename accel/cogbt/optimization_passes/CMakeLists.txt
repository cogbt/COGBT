cmake_minimum_required(VERSION 3.13)

# read environment variable LLVM_HOME
set(LLVM_HOME $ENV{LLVM_HOME})

# if LLVM_HOME is null, using default llvm path
if (NOT LLVM_HOME)
    set(LLVM_HOME "$ENV{HOME}/llvm15")
endif()

if (NOT EXISTS "${LLVM_HOME}")
    message(FATAL_ERROR "You should define environment variable LLVM_HOME")
endif()

message("LLVM_HOME: ${LLVM_HOME}")

SET(CMAKE_CXX_FLAGS "-Wall -fno-rtti")
# generate compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(OptimizationPasses)

link_directories(${LLVM_HOME}/lib)
include_directories(${LLVM_HOME}/include)

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
