SET(sems_module_name radius_client)

SET(radius_client_SRCS
	RadiusClient.cpp
	RadiusPacket.cpp
	RadiusConnection.cpp
	RadiusAuthConnection.cpp
	RadiusAccConnection.cpp
)

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
