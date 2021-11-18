
# Copyright (c) <current-year> <your-organization>
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# file(GLOB_RECURSE DIR_OS CONFIGURE_DEPENDS /usr/local/lib/x86_64-linux-gnu/*.so)
unset(MYPLUGIN_LINK_LIBRARIES)

vpp_plugin_find_library(myplugin PARSINGRS "libparser_rs.so")
if (NOT PARSINGRS)
  message(WARNING "-- libparsing_rs.so not found - myplugin disabled!")
  return()
endif()
list(APPEND MYPLUGIN_LINK_LIBRARIES ${PARSINGRS})

add_vpp_plugin(myplugin
  SOURCES
  myplugin.c
  node.c
  myplugin_periodic.c
  myplugin.h
  # parser_rs.h

  MULTIARCH_SOURCES
  node.c

  API_FILES
  myplugin.api

  API_TEST_SOURCES
  myplugin_test.c

  LINK_LIBRARIES
  ${MYPLUGIN_LINK_LIBRARIES}
  # LINK_LIBRARIES ${DIR_OS}
)
