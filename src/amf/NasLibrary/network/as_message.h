/*****************************************************************************

Source      as_message.h

Version     0.1

Date        2019/08/05

Product     NAS stack

Subsystem   include

Author      BUPT

Description Contains network's global definitions

*****************************************************************************/
#ifndef __AS_MESSAGE_H__
#define __AS_MESSAGE_H__

#include "networkDef.h"
/*
 * --------------------------------------------------------------------------
 *          NAS signalling connection establishment
 * --------------------------------------------------------------------------
 */

/* Cause of RRC connection establishment, origin from typedef enum Ngap_RRCEstablishmentCause*/
typedef enum as_cause_s {
	AS_CAUSE_EMERGENCY              = NGAP_RRC_ESTABLISHMENT_CAUSE_EMERGENCY, 
	AS_CAUSE_HIGH_PRIORITY_ACCESS   = NGAP_RRC_ESTABLISHMENT_CAUSE_HIGH_PRIORITY_ACCESS, 
	AS_CAUSE_MT_ACCESS              = NGAP_RRC_ESTABLISHMENT_CAUSE_MT_ACCESS,  
	AS_CAUSE_MO_SIGNALLING          = NGAP_RRC_ESTABLISHMENT_CAUSE_MO_SIGNALLING,
	AS_CAUSE_MO_DATA                = NGAP_RRC_ESTABLISHMENT_CAUSE_MO_DATA,  
	AS_CAUSE_MO_VOICECALL           = NGAP_RRC_ESTABLISHMENT_CAUSE_MO_VOICECALL ,
	AS_CAUSE_MO_VIDEOCALL           = NGAP_RRC_ESTABLISHMENT_CAUSE_MO_VIDEOCALL, 
	AS_CAUSE_MO_SMS                 = NGAP_RRC_ESTABLISHMENT_CAUSE_MO_SMS,  
	AS_CAUSE_MPS_PRIORITY_ACCESS    = NGAP_RRC_ESTABLISHMENT_CAUSE_MPS_PRIORITY_ACCESS, 
	AS_CAUSE_MCS_PRIORITY_ACCESS    = NGAP_RRC_ESTABLISHMENT_CAUSE_MCS_PRIORITY_ACCESS 
} as_cause_t;

#endif

