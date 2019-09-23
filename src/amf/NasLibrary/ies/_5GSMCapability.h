#ifndef __5GSMCAPABILITY_H_
#define __5GSMCAPABILITY_H_


#include <stdint.h>
#include <stdbool.h>
#include "bstrlib.h"

#define _5GSM_CAPABILITY_MINIMUM_LENGTH 3
#define _5GSM_CAPABILITY_MAXIMUM_LENGTH 15


#define REFLECTIVE_QOS_NOT_SUPPORTED 					0
#define REFLECTIVE_QOS_SUPPORTED     					1
#define MULTI_HOMED_IPV6_PDU_SESSION_NOT_SUPPORTED 		0
#define MULTI_HOMED_IPV6_PDU_SESSION_SUPPORTED     		1
#define ETHERNET_PDN_TYPE_IN_S1_MODE_NOT_SUPPORTED 		0
#define ETHERNET_PDN_TYPE_IN_S1_MODE_SUPPORTED 			1
#define EATSSS_LOW_LAYER_FUNCTIONALITY_NOT_SUPPORTED 	0
#define EATSSS_LOW_LAYER_FUNCTIONALITY_SUPPORTED 		1
#define MPTCP_FUNCTIONALITY_NOT_SUPPORTED 				0
#define MPTCP_FUNCTIONALITY_SUPPORTED 					1

typedef struct{
	bool is_Rqos_supported;
  	bool is_MH6PDU_supported;
  	bool is_EPTS1_supported;
	bool is_ATSLL_supported;
	bool is_MPTCP_supported;
	//bstring _5GSMCapability_spare;
}_5GSMCapability;


int encode__5gsm_capability ( _5GSMCapability _5gsmcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode__5gsm_capability ( _5GSMCapability * _5gsmcapability, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif
