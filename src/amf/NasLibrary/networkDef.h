/*****************************************************************************

Source      networkDef.h

Version     0.1

Date        2019/08/05

Product     NAS stack

Subsystem   include

Author      BUPT

Description Contains network's global definitions

*****************************************************************************/
#ifndef __NETWORK_DEF_H__
#define __NETWORK_DEF_H__

/*
 * --------------------------------------
 * Network connection establishment cause
 * --------------------------------------
 */

#define NGAP_RRC_ESTABLISHMENT_CAUSE_EMERGENCY 0
#define NGAP_RRC_ESTABLISHMENT_CAUSE_HIGH_PRIORITY_ACCESS 1
#define NGAP_RRC_ESTABLISHMENT_CAUSE_MT_ACCESS  2
#define NGAP_RRC_ESTABLISHMENT_CAUSE_MO_SIGNALLING 3
#define NGAP_RRC_ESTABLISHMENT_CAUSE_MO_DATA  4
#define NGAP_RRC_ESTABLISHMENT_CAUSE_MO_VOICECALL 5
#define NGAP_RRC_ESTABLISHMENT_CAUSE_MO_VIDEOCALL 6
#define NGAP_RRC_ESTABLISHMENT_CAUSE_MO_SMS  7
#define NGAP_RRC_ESTABLISHMENT_CAUSE_MPS_PRIORITY_ACCESS 8
#define NGAP_RRC_ESTABLISHMENT_CAUSE_MCS_PRIORITY_ACCESS 9

#endif

