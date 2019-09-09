cmake_minimum_required (VERSION 3.2)

set (OPENAIR5GCN_DIR  $ENV{OPENAIR5GCN_DIR})
set (BUILD_TOP_DIR    ${OPENAIR5GCN_DIR}/build)
set (OPENAIR5GCN_BIN_DIR  ${CMAKE_CURRENT_BINART_DIR}${CMAKE_FILES_DIRECTORY})
message(${OPENAIR5GCN_BIN_DIR})
project(amf)

set(CMAKE_MODULE_PATH "${BUILD_TOP_DIR}/modules/")
set(CMAKE_MODULE_PATH "${OPENAIR5GCN_DIR}/build/modules" "${CMAKE_MODULE_PATH}")
include(FindPkgConfig)

###########################################
# macros to define options as there is numerous options in oai
################################################
macro(add_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  add_definitions("-D${name}=${value}")
endmacro(add_option)

macro(add_boolean_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY TYPE BOOL)
  if (${value})
    add_definitions("-D${name}=1")
  else (${value})
    add_definitions("-D${name}=0")
  endif (${value})
endmacro(add_boolean_option)

macro(add_integer_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  add_definitions("-D${name}=${value}")
endmacro(add_integer_option)

macro(add_list1_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY STRINGS ${ARGN})
  if(NOT "${value}" STREQUAL "False")
    add_definitions("-D${name}=${value}")
  endif()
endmacro(add_list1_option)

macro(add_list2_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY STRINGS ${ARGN})
  if(NOT "${value}" STREQUAL "False")
    add_definitions("-D${value}=1")
  endif()
endmacro(add_list2_option)

macro(add_list_string_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY STRINGS ${ARGN})
  if(NOT "${value}" STREQUAL "False")
    add_definitions("-D${name}=\"${value}\"")
  endif()
endmacro(add_list_string_option)


################################################################
# Compilation flags
################################################################
# Build type
################################################################
if (CMAKE_BUILD_TYPE STREQUAL "")
   set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()
add_list_string_option(CMAKE_BUILD_TYPE "RelWithDebInfo" "Choose the type of build, options are: None(CMAKE_CXX_FLAGS or CMAKE_C_FLAGS used) Debug Release RelWithDebInfo MinSizeRel." Debug Release RelWithDebInfo MinSizeRel)
Message("Build type is ${CMAKE_BUILD_TYPE}")
if (CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
  add_boolean_option(LOG_OAI True         "Thread safe logging API")
  add_boolean_option(LOG_OAI_MINIMAL True "Thread safe logging API, log only levels above NOTICE")
endif()
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_boolean_option(LOG_OAI True "Thread safe logging API")
  add_boolean_option(DEBUG_IS_ON True "Thread safe logging API")
  add_boolean_option(TRACE_IS_ON True "Thread safe tracing API")
endif()

###############################################################################
# Debug and build related options
###############################################################################
add_boolean_option( DAEMONIZE                       False    "Fork executable if true")

add_boolean_option( DISABLE_ITTI_DETECT_SUB_TASK_ID False    " ")
add_boolean_option( DISPLAY_LICENCE_INFO            False    "If a module has a licence banner to show")
add_boolean_option( ENABLE_ITTI                     True     "ITTI is internal messaging, should remain enabled for most targets")
add_boolean_option( ENABLE_ITTI_ANALYZER            False    "ITTI Analyzer is a GUI based on GTK that displays the ITTI messages exchanged between tasks")
add_integer_option( ITTI_TASK_STACK_SIZE            0        "pthread allocated stack size in bytes of an ITTI task, if 0, use default stack size ")
add_integer_option( ITTI_LITE                       0        "Do not use ITTI systematically for each message exchanged between layer modules")
add_boolean_option( MESSAGE_CHART_GENERATOR         False    "For generating sequence diagrams")
add_boolean_option( DISABLE_EXECUTE_SHELL_COMMAND   False    "disable execution of C int system(const char *command);")
# NAS LAYER OPTIONS
##########################
add_boolean_option( EPC_BUILD                       False    "BUILD MME-xGW executable")
add_boolean_option( GTPV1U_LINEAR_TEID_ALLOCATION   False    "Teid allocation id mode versus pseudo random")
# S1AP LAYER OPTIONS
##########################
add_boolean_option(S1AP_DEBUG_LIST                  False    "Traces, option to be removed soon")
# SCTP LAYER OPTIONS
##########################
add_boolean_option(SCTP_DUMP_LIST                   False    "Traces, option to be removed soon")

add_boolean_option( TRACE_HASHTABLE                 False    "Trace hashtables operations ")
add_boolean_option( LOG_OAI                         False    "Thread safe logging utility")
add_boolean_option( LOG_OAI_CLEAN_HARD              False    "Thread safe logging utility option for cleaning inner structs")
add_boolean_option( SECU_DEBUG                      False    "Traces, option to be removed soon")

add_boolean_option( NAS_FORCE_REJECT_SR             True     "TEMP, TO be disabled for community after development and test: Force the EMM NAS layer to respond to any SR by reject")
add_boolean_option( NAS_FORCE_REJECT_TAU            True     "TEMP, TO be disabled for community after development and test: Force the EMM NAS layer to respond to any TAU Request by reject")

add_boolean_option( TRACE_3GPP_SPEC                 True     "Log hits of 3GPP specifications requirements")

pkg_search_module(NETTLE nettle)
if(NOT ${NETTLE_FOUND})
  message("PACKAGE nettle not found: some targets will fail")
else()
  include_directories(${NETTLE_INCLUDE_DIRS})
endif()

pkg_search_module(NETTLE nettle)
if(NOT ${NETTLE_FOUND})
  message( FATAL_ERROR "PACKAGE nettle not found: some targets will fail. Run SCRIPTS/build_mme -i or SCRIPTS/build_hss -i  again!")
else()
  include_directories(${NETTLE_INCLUDE_DIRS})
endif()

message ("NETTLE VERSION_INSTALLED  = ${NETTLE_VERSION}")

pkg_search_module(CRYPTO libcrypto REQUIRED)
include_directories(${CRYPTO_INCLUDE_DIRS})

pkg_search_module(CONFIG libconfig REQUIRED)
include_directories(${CONFIG_INCLUDE_DIRS})

string(REGEX REPLACE "([0-9]+).*" "\\1" NETTLE_VERSION_MAJOR ${NETTLE_VERSION})
string(REGEX REPLACE "[0-9]+\\.([0-9]+).*" "\\1" NETTLE_VERSION_MINOR ${NETTLE_VERSION})
message ("NETTLE_VERSION_MAJOR = ${NETTLE_VERSION_MAJOR}")
message ("NETTLE_VERSION_MINOR = ${NETTLE_VERSION_MINOR}")

if ("${NETTLE_VERSION_MAJOR}" STREQUAL "" OR "${NETTLE_VERSION_MINOR}" STREQUAL "")
  message( FATAL_ERROR "The nettle version not detected properly. Try to run SCRIPTS/build_mme -i or SCRIPTS/build_hss -i again" )
endif()

add_definitions("-DNETTLE_VERSION_MAJOR=${NETTLE_VERSION_MAJOR}")
add_definitions("-DNETTLE_VERSION_MINOR=${NETTLE_VERSION_MINOR}")


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pg -g3 -fpermissive" )
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -fstack-protector-all -g -DMALLOC_CHECK_=3 -DDEBUG_IS_ON=1 -DTRACE_IS_ON=1 -O0")
########################################################
## ASN.1 grammer C code
#######################################################
set (asn1c_call "${BUILD_TOP_DIR}/tools/generate_asn1")
set (asn1_generated_dir ${OPENAIR5GCN_BIN_DIR})

set (NGAP_DIR ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer)
set (ASN1RELDIR r15.2)
set (NGAP_ASN_DIR ${NGAP_DIR}/messages/asn1/${ASN1RELDIR})
set (NGAP_ASN_FILES 
    ${NGAP_ASN_DIR}/NGAP-CommonDataTypes.asn
    ${NGAP_ASN_DIR}/NGAP-Constants.asn
    ${NGAP_ASN_DIR}/NGAP-IEs.asn
    ${NGAP_ASN_DIR}/NGAP-Containers.asn
    ${NGAP_ASN_DIR}/NGAP-PDU.asn

    )
#set (NGAP_C_DIR ${OPENAIR5GCNDIR}/build/amf/build/${ASN1RELDIR})
set (NGAP_C_DIR ${OPENAIR5GCNDIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/messages/asn1/r15.2/generated_ngap)
#set (NGAP_C_DIR ${asn1_generated_dir}/${ASN1RELDIR})
#execute_process(COMMAND ${asn1c_call} ${NGAP_C_DIR} ${NGAP_ASN_FILES})
#file(GLOB NGAP_source ${NGAP_C_DIR}/*.c)
#message(${NGAP_C_DIR})
set(NGAP_OAI_generated
  ${NGAP_C_DIR}/ngap_decoder.c
  ${NGAP_C_DIR}/ngap_encoder.c
  ${NGAP_C_DIR}/ngap_xer_print.c
  ${NGAP_C_DIR}/ngap_ies_defs.h
  )
#file(GLOB ngap_h ${NGAP_C_DIR}/*.h)
#add_custom_command (
#  OUTPUT ${NGAP_OAI_generated}
#  COMMAND ${asn1c_call} ${NGAP_C_DIR} ${NGAP_ASN_FILES}
#  COMMAND python ${NGAP_DIR}/messages/asn1/asn1tostruct.py -f${NGAP_ASN_DIR}/NGAP-PDU-Contents.asn -o${NGAP_C_DIR}
#  DEPENDS ${NGAP_ASN_FILES}
#  )

include_directories ("${NGAP_C_DIR}")

############################################################

###########################################################
# ITTI 
#########################################################
set(ittiPath ${OPENAIR5GCN_DIR}/src/amf/IttiLibrary)
set(ITTICFiles
    ${ittiPath}/inc/backtrace.c
    ${ittiPath}/inc/bstrlib.c
    ${ittiPath}/inc/intertask_interface.c
    ${ittiPath}/inc/intertask_interface_dump.c
    ${ittiPath}/inc/memory_pools.c
    ${ittiPath}/inc/signals.c
    ${ittiPath}/inc/timer.c
    ${ittiPath}/inc/dynamic_memory_check.c
)
set(LFDS ${ittiPath}/lib/liblfds611.a)
include_directories(${ittiPath}/inc)

########################################################
include_directories(/usr/local/include/nlohmann)
include_directories(/usr/local/include/pistache)
link_directories(/usr/local/lib)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/CommService/api)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/CommService/impl)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/EvetService/api)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/EvetService/impl)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/LocService/api)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/LocService/impl)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/MtService/api)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/MtService/impl)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/AmfGeneratedDataModels)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/common)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/N1N2ProtocolStack/AmfSctpLayer)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/utils)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/N1N2ProtocolStack/AmfNgapLayer)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/AmfAppLayer)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../build/amf/build/r15.2)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/N1N2ProtocolStack/AmfNgapLayer/messages/asn1/r15.2/generated_ngap)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/Security)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/network)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/test)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/ies)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/mm)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/mm/msg)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/sm/msg)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/N1N2ProtocolStack/AmfNasLayer)
#include_directories(${NGAP_C_DIR})

file(GLOB NAS_C_CODE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/Security/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/*.c
    #${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/test/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/ies/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/mm/msg/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/sm/msg/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/utils/TLVDecoder.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/utils/TLVEncoder.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/NasLibrary/*.c)



#file(GLOB ASN1_C_FILES ${NGAP_C_DIR}/*.c)
#file(GLOB ASN1_C_FILES ${CMAKE_CURRENT_SOURCE_DIR}/../../build/amf/build/r15.2/*.c)
file(GLOB ASN1_C_FILES ${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/N1N2ProtocolStack/AmfNgapLayer/messages/asn1/r15.2/generated_ngap/*.c)

file(GLOB NGAP_LAYER_SOURCE_CODE
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_common.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_setup_response.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_setup_failure.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_downlink_nas_transport.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_handlers.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_decoder.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_encoder.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_itti_messaging.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_ta.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_nas_procedures.c
    )
file(GLOB NGAP_LIB_SOURCE_CODE
    NGAP_C_DIR/*.c)

file(GLOB NAS_LAYER_SOURCE_CODE
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNasLayer/nas_amf.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNasLayer/nas_amf_handlers.c
    )
    

file(GLOB SRCS
    #${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/*.cpp
    #${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/CommService/api/*.cpp
    #${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/CommService/impl/*.cpp
    #${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/EvetService/api/*.cpp
    #${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/EvetService/impl/*.cpp
    #${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/LocService/api/*.cpp
    #${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/LocService/impl/*.cpp
    #${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/MtService/api/*.cpp
    #${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/MicroServiceProtocolStack/MtService/impl/*.cpp
    #${CMAKE_CURRENT_SOURCE_DIR}/../../src/amf/AmfGeneratedDataModels/*.cpp
    #${OPENAIR5GCN_DIR}/src/amf/AmfMain.cpp
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfSctpLayer/sctp_itti_messaging.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfSctpLayer/sctp_primitives_server.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfSctpLayer/sctp_primitives_client.c 
    ${OPENAIR5GCN_DIR}/src/amf/utils/conversions.c
    ${OPENAIR5GCN_DIR}/src/amf/utils/pid_file.c
    ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfSctpLayer/sctp_common.c
    #${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf.c
    #${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_common.c
    #${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_handlers.c
    #${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_decoder.c
    #${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_encoder.c
    #${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_itti_messaging.c
    #${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_ta.c
    #${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/ngap_amf_nas_procedures.c
    ${OPENAIR5GCN_DIR}/src/amf/utils/log.c
    ${OPENAIR5GCN_DIR}/src/amf/utils/hashtable.c
    ${OPENAIR5GCN_DIR}/src/amf/utils/obj_hashtable.c
    ${OPENAIR5GCN_DIR}/src/amf/AmfAppLayer/amf_app.c
    ${OPENAIR5GCN_DIR}/src/amf/AmfAppLayer/amf_config.c
    ${OPENAIR5GCN_DIR}/src/amf/AmfAppLayer/amf_app_defs.c
    ${OPENAIR5GCN_DIR}/src/amf/AmfAppLayer/amf_app_itti_messaging.c
    ${OPENAIR5GCN_DIR}/src/amf/AmfAppLayer/amf_app_statistics.c
    #${OPENAIR5GCN_DIR}/src/amf/AmfAppLayer/amf_app_bearer.c
    #${CMAKE_CURRENT_SOURCE_DIR}/../../build/amf/build/r15.2/ngap_decoder.c
    #${CMAKE_CURRENT_SOURCE_DIR}/../../build/amf/build/r15.2/ngap_encoder.c
    #${CMAKE_CURRENT_SOURCE_DIR}/../../build/amf/build/r15.2/ngap_xer_print.c
    #${CMAKE_CURRENT_SOURCE_DIR}/../../build/amf/build/r15.2/*.c
    #${OPENAIR5GCN_DIR}/build/amf/build/r15.2/*.c
)

#add_executable(${PROJECT_NAME} ${OPENAIR5GCN_DIR}/src/amf/AmfMain.cpp ${SRCS} ${ITTICFiles} ${ASN1_C_FILES} ${NAS_C_CODE} ${NAS_LAYER_SOURCE_CODE} ${NGAP_LAYER_SOURCE_CODE} ${NGAP_LIB_SOURCE_CODE} )
#target_link_libraries(${PROJECT_NAME} pistache pthread rt ${LFDS} sctp ${NETTLE_LIBRARIES} ${CRYPTO_LIBRARIES} m ${CONFIG_LIBRARIES})

#add_executable(ngap ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfNgapLayer/example/ngapTestMain.c ${SRCS} ${ITTICFiles} ${ASN1_C_FILES} ${NAS_C_CODE} ${NGAP_LAYER_SOURCE_CODE} ${NGAP_LIB_SOURCE_CODE})
#target_link_libraries(ngap pistache pthread rt ${LFDS} sctp ${NETTLE_LIBRARIES} ${NETTLE_LIBRARIES} ${CRYPTO_LIBRARIES} m ${CONFIG_LIBRARIES})

add_executable(nas ${OPENAIR5GCN_DIR}/src/amf/NasLibrary/test/NasMain.c ${SRCS} ${ITTICFiles} ${ASN1_C_FILES} ${NAS_C_CODE} ${NGAP_LAYER_SOURCE_CODE} ${NGAP_LIB_SOURCE_CODE} )
target_link_libraries(nas pistache pthread rt ${LFDS} sctp crypt ${NETTLE_LIBRARIES} ${CRYPTO_LIBRARIES}  m ${CONFIG_LIBRARIES})


#add_executable(fake_gNB ${OPENAIR5GCN_DIR}/src/amf/test/NGSetupRequest.c ${OPENAIR5GCN_DIR}/src/amf/N1N2ProtocolStack/AmfSctpLayer/sctp_primitives_client.c ${SRCS} ${ITTICFiles} ${ASN1_C_FILES} ${NGAP_LAYER_SOURCE_CODE} ${NGAP_LIB_SOURCE_CODE} )
#target_link_libraries(fake_gNB pistache pthread rt ${LFDS} sctp ${NETTLE_LIBRARIES}  ${CRYPTO_LIBRARIES} m ${CONFIG_LIBRARIES})
