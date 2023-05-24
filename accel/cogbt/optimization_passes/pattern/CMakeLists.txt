get_filename_component(CURRENT_DIR ${CMAKE_CURRENT_SOURCE_DIR} NAME)
add_library(${CURRENT_DIR} OBJECT pattern-reduction.cpp)
