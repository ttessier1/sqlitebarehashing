# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.12)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

add_compile_definitions(__ALL__)
add_compile_definitions(__USE_BLOB__)

project(barehashing)

add_library(barehashing SHARED sqlite_hashing.cpp crypto_hashing.cpp crypto_hashing.h algorithms.h digestsize.h global.h md2.cpp md2.h md4.cpp md4.h md5.cpp md5.h sha1.cpp sha224-256.cpp sha384-512.cpp usha.cpp sha.h util.cpp util.h ) 

target_link_directories(barehashing PUBLIC "../../sqlite/lib")
target_link_directories(barehashing PUBLIC "../../sqlite")
target_link_directories(barehashing PUBLIC "./")
add_library(sqlite3.lib STATIC IMPORTED) # or STATIC instead of SHARED
set_target_properties(sqlite3.lib PROPERTIES
  IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/../../sqlite"
)
set_target_properties(sqlite3.lib PROPERTIES
  IMPORTED_LOCATION "${PROJECT_SOURCE_DIR}/../"
)
find_library(barehashing sqlite3)
if(WIN32)
  set(SQLITE_INCLUDE_DIR "../../sqlite/include" CACHE FILEPATH "../../sqlite/include")

  if(NOT EXISTS ${SQLITE_INCLUDE_DIR}/sqlite3.h)
    message(SEND_ERROR "Can't find sqlite3.h in ${SQLITE_INCLUDE_DIR})
  endif()
  if(NOT EXISTS ${SQLITE_INCLUDE_DIR}/sqlite3ext.h)
    message(SEND_ERROR "Can't find sqlite3ext.h in ${SQLITE_INCLUDE_DIR})
  endif()
  include_directories(${SQLITE_INCLUDE_DIR})
endif()

target_include_directories(barehashing PRIVATE "${PROJECT_SOURCE_DIR}/../../sqlite")
target_include_directories(barehashing PRIVATE "/usr/include")
target_link_libraries(barehashing sqlite3)



