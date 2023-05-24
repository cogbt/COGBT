get_filename_component(CURRENT_DIR ${CMAKE_CURRENT_SOURCE_DIR} NAME)
add_library(${CURRENT_DIR} OBJECT flag-reduction.cpp)

#target_link_libraries(${OUTPUT_LIBRARY} PRIVATE ${CURRENT_DIR})
