set (jsonrpc_SRCS
JsonRPC.cpp
JsonRPCServer.cpp
RpcPeer.cpp
RpcServerLoop.cpp
RpcServerThread.cpp
WsRpcPeer.cpp
SecureRpcPeer.cpp
)

SET(jsonrpc_config_files "")
SET(jsonrpc_config_dist_files jsonrpc)

ADD_DEFINITIONS(-I${LIBEV_INCLUDE_DIR})
SET(sems_module_name jsonrpc)
SET(sems_module_libs ${sems_module_libs} ev)
INCLUDE(${CMAKE_SOURCE_DIR}/cmake/module.rules.txt)
