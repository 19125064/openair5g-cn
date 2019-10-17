#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "PDUSessionIdentity.h"
#include "ProcedureTransactionIdentity.h"
#include "MessageType.h"
#include "_5GSMCause.h"
#include "SessionAMBR.h"
#include "GPRSTimer.h"
#include "AlwaysonPDUSessionIndication.h"
#include "QOSRules.h"
#include "MappedEPSBearerContexts.h"
#include "QOSFlowDescriptions.h"
#include "ExtendedProtocolConfigurationOptions.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define PDU_SESSION_MODIFICATION_COMMAND_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MINIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		_5GSM_CAUSE_MINIMUM_LENGTH + \
		SESSION_AMBR_MINIMUM_LENGTH + \
		GPRS_TIMER_MINIMUM_LENGTH + \
		ALWAYSON_PDU_SESSION_INDICATION_MINIMUM_LENGTH + \
		QOS_RULES_MINIMUM_LENGTH + \
		MAPPED_EPS_BEARER_CONTEXTS_MINIMUM_LENGTH + \
		QOS_FLOW_DESCRIPTIONS_MINIMUM_LENGTH + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define PDU_SESSION_MODIFICATION_COMMAND_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MAXIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		_5GSM_CAUSE_MAXIMUM_LENGTH + \
		SESSION_AMBR_MAXIMUM_LENGTH + \
		GPRS_TIMER_MAXIMUM_LENGTH + \
		ALWAYSON_PDU_SESSION_INDICATION_MAXIMUM_LENGTH + \
		QOS_RULES_MAXIMUM_LENGTH + \
		MAPPED_EPS_BEARER_CONTEXTS_MAXIMUM_LENGTH + \
		QOS_FLOW_DESCRIPTIONS_MAXIMUM_LENGTH + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MAXIMUM_LENGTH + \
0)

#define PDU_SESSION_MODIFICATION_COMMAND__5GSM_CAUSE_IEI						0x59
#define PDU_SESSION_MODIFICATION_COMMAND_SESSION_AMBR_IEI						0x2A
#define PDU_SESSION_MODIFICATION_COMMAND_GPRS_TIMER_IEI							0x56
#define PDU_SESSION_MODIFICATION_COMMAND_ALWAYSON_PDU_SESSION_INDICATION_IEI	0x80
#define PDU_SESSION_MODIFICATION_COMMAND_QOS_RULES_IEI							0x7A
#define PDU_SESSION_MODIFICATION_COMMAND_MAPPED_EPS_BEARER_CONTEXTS_IEI			0x75
#define PDU_SESSION_MODIFICATION_COMMAND_QOS_FLOW_DESCRIPTIONS_IEI				0x79
#define PDU_SESSION_MODIFICATION_COMMAND_E_P_C_O_IEI							0x7B

#define PDU_SESSION_MODIFICATION_COMMAND__5GSM_CAUSE_PRESENCE						(1<<0)
#define PDU_SESSION_MODIFICATION_COMMAND_SESSION_AMBR_PRESENCE						(1<<1)
#define PDU_SESSION_MODIFICATION_COMMAND_GPRS_TIMER_PRESENCE						(1<<2)
#define PDU_SESSION_MODIFICATION_COMMAND_ALWAYSON_PDU_SESSION_INDICATION_PRESENCE	(1<<3)
#define PDU_SESSION_MODIFICATION_COMMAND_QOS_RULES_PRESENCE							(1<<4)
#define PDU_SESSION_MODIFICATION_COMMAND_MAPPED_EPS_BEARER_CONTEXTS_PRESENCE		(1<<5)
#define PDU_SESSION_MODIFICATION_COMMAND_QOS_FLOW_DESCRIPTIONS_PRESENCE				(1<<6)
#define PDU_SESSION_MODIFICATION_COMMAND_E_P_C_O_PRESENCE							(1<<7)


typedef struct pdu_session_modification_command_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	PDUSessionIdentity pdusessionidentity;
	ProcedureTransactionIdentity proceduretransactionidentity;
	MessageType messagetype;
	uint8_t presence;
	_5GSMCause _5gsmcause;
	SessionAMBR sessionambr;
	GPRSTimer gprstimer;
	AlwaysonPDUSessionIndication alwaysonpdusessionindication;
	QOSRules qosrules;
	MappedEPSBearerContexts mappedepsbearercontexts;
	QOSFlowDescriptions qosflowdescriptions;
	ExtendedProtocolConfigurationOptions extendedprotocolconfigurationoptions;
}pdu_session_modification_command_msg;


int decode_pdu_session_modification_command(pdu_session_modification_command_msg *pdusessionmodificationcommand, uint8_t *buffer, uint32_t len);
int encode_pdu_session_modification_command(pdu_session_modification_command_msg *pdusessionmodificationcommand, uint8_t *buffer, uint32_t len);
