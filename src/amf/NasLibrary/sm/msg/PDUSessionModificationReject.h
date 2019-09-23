#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "PDUSessionIdentity.h"
#include "ProcedureTransactionIdentity.h"
#include "MessageType.h"
#include "_5GSMCause.h"
#include "GPRSTimer3.h"
#include "ExtendedProtocolConfigurationOptions.h"
#include "_5GSMCongestionReattemptIndicator.h"



/* Minimum length macro. Formed by minimum length of each mandatory field */
#define PDU_SESSION_MODIFICATION_REJECT_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MINIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		_5GSM_CAUSE_MINIMUM_LENGTH + \
		GPRS_TIMER3_MINIMUM_LENGTH + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define PDU_SESSION_MODIFICATION_REJECT_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MAXIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		_5GSM_CAUSE_MAXIMUM_LENGTH + \
		GPRS_TIMER3_MAXIMUM_LENGTH + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MAXIMUM_LENGTH + \
0)

#define PDU_SESSION_MODIFICATION_REJECT_GPRS_TIMER3_IEI								0x37
#define PDU_SESSION_MODIFICATION_REJECT_E_P_C_O_IEI									0x7B
#define PDU_SESSION_MODIFICATION_REJECT__5GSM_CONGESTION_REATTEMPT_INDICATOR_IEI	0x61

#define PDU_SESSION_MODIFICATION_REJECT_GPRS_TIMER3_PRESENCE							(1<<0)
#define PDU_SESSION_MODIFICATION_REJECT_E_P_C_O_PRESENCE								(1<<1)
#define PDU_SESSION_MODIFICATION_REJECT__5GSM_CONGESTION_REATTEMPT_INDICATOR_PRESENCE	(1<<2)

typedef struct pdu_session_modification_reject_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	PDUSessionIdentity pdusessionidentity;
	ProcedureTransactionIdentity proceduretransactionidentity;
	MessageType messagetype;
	_5GSMCause _5gsmcause;
	uint8_t presence;
	GPRSTimer3 gprstimer3;
	ExtendedProtocolConfigurationOptions extendedprotocolconfigurationoptions;
	_5GSMCongestionReattemptIndicator _5gsmcongestionreattemptindicator;
}pdu_session_modification_reject_msg;


int decode_pdu_session_modification_reject(pdu_session_modification_reject_msg *pdusessionmodificationreject, uint8_t *buffer, uint32_t len);
int encode_pdu_session_modification_reject(pdu_session_modification_reject_msg *pdusessionmodificationreject, uint8_t *buffer, uint32_t len);
