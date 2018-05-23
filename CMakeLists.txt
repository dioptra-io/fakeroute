cmake_minimum_required(VERSION 3.8)
project(fakeRouteC__)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
set(SOURCE_FILES main.cpp Router.cpp Router.hpp Router.fwd.hpp SimpleRoute.cpp SimpleRoute.hpp Topology.cpp Topology.hpp)
FIND_PACKAGE( Boost 1.62 COMPONENTS program_options REQUIRED )
INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} )

add_executable(fakeRouteC__ ${SOURCE_FILES})

target_link_libraries(fakeRouteC__ PUBLIC tins netfilter_queue ${Boost_LIBRARIES})