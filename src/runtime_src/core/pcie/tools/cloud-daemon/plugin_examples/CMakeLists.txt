if (NOT ${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  )

file(GLOB BAREMETAL_PLUGIN_FILES
  "baremetal.h"
  "baremetal.cpp"
  )

add_library(betametal_plugin OBJECT ${BAREMETAL_PLUGIN_FILES})

add_library(baremetal_mpd_plugin SHARED ""
  $<TARGET_OBJECTS:betametal_plugin>
)

add_compile_options("-fPIC")

target_link_libraries(baremetal_mpd_plugin
  xrt_core_static
  xrt_coreutil_static
  uuid
  boost_filesystem
  boost_system
  pthread
  rt
  )

install(TARGETS baremetal_mpd_plugin
        LIBRARY
        DESTINATION ${XRT_INSTALL_DIR}/lib
		)
endif (NOT ${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
