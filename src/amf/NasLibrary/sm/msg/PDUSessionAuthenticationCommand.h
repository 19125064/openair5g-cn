#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "PDUSessionIdentity.h"
#include "ProcedureTransactionIdentity.h"
#include "MessageType.h"
#include "EAPMessage.h"
#include "ExtendedProtocolConfigurationOptions.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define PDU_SESSION_AUTHENTICATION_COMMAND_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MINIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		EAP_MESSAGE_MINIMUM_LENGTH + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define PDU_SESSION_AUTHENTICATION_COMMAND_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MAXIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		EAP_MESSAGE_MAXIMUM_LENGTH + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MAXIMUM_LENGTH + \
0)

#define PDU_SESSION_AUTHENTICATION_COMMAND_E_P_C_O_IEI			0x7B
#define PDU_SESSION_AUTHENTICATION_COMMAND_E_P_C_O_PRESENCE		(1<<0)

typedef struct pdu_session_authentication_command_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	PDUSessionIdentity pdusessionidentity;
	ProcedureTransactionIdentity proceduretransactionidentity;
	MessageType messagetype;
	EAPMessage eapmessage;
	uint8_t presence;
	ExtendedProtocolConfigurationOptions extendedprotocolconfigurationoptions;
}pdu_session_authentication_command_msg;


int decode_pdu_session_authentication_command(pdu_session_authentication_command_msg *pdusessionauthenticationcommand, uint8_t *buffer, uint32_t len);
int encode_pdu_session_authentication_command(pdu_session_authentication_command_msg *pdusessionauthenticationcommand, uint8_t *buffer, uint32_t len);
