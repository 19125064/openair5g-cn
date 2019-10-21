#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "PDUSessionIdentity.h"
#include "ProcedureTransactionIdentity.h"
#include "MessageType.h"
#include "_5GSMCause.h"

#if 0
/* Minimum length macro. Formed by minimum length of each mandatory field */
#define _5GSM_STATUS_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MINIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		_5GSM_CAUSE_MINIMUM_LENGTH + \
0)
#endif
/* Minimum length macro. Formed by minimum length of each mandatory field */
#define _5GSM_STATUS_MINIMUM_LENGTH ( \
		_5GSM_CAUSE_MINIMUM_LENGTH_V + \
0)


/* Maximum length macro. Formed by maximum length of each field */
#define _5GSM_STATUS_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MAXIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		_5GSM_CAUSE_MAXIMUM_LENGTH_V + \
0)

typedef struct _5gsm_status_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	PDUSessionIdentity pdusessionidentity;
	ProcedureTransactionIdentity proceduretransactionidentity;
	MessageType messagetype;
	_5GSMCause _5gsmcause;
}_5gsm_status_msg;


int decode__5gsm_status(_5gsm_status_msg *_5gsmstatus, uint8_t *buffer, uint32_t len);
int encode__5gsm_status(_5gsm_status_msg *_5gsmstatus, uint8_t *buffer, uint32_t len);
