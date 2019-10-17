#include <stdint.h>

#include "ExtendedProtocolDiscriminator.h"
#include "PDUSessionIdentity.h"
#include "ProcedureTransactionIdentity.h"
#include "MessageType.h"
#include "IntergrityProtectionMaximumDataRate.h"
#include "_PDUSessionType.h"
#include "SSCMode.h"
#include "_5GSMCapability.h"
#include "MaximumNumberOfSupportedPacketFilters.h"
#include "AlwaysonPDUSessionRequested.h"
#include "SMPDUDNRequestContainer.h"
#include "ExtendedProtocolConfigurationOptions.h"


/* Minimum length macro. Formed by minimum length of each mandatory field */
#define PDU_SESSION_ESTABLISHMENT_REQUEST_MINIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MINIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MINIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MINIMUM_LENGTH + \
		MESSAGE_TYPE_MINIMUM_LENGTH + \
		INTERGRITY_PROTECTION_MAXIMUM_DATA_RATE_MINIMUM_LENGTH + \
		_PDU_SESSION_TYPE_MINIMUM_LENGTH + \
		SSC_MODE_MINIMUM_LENGTH + \
		_5GSM_CAPABILITY_MINIMUM_LENGTH + \
		MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS_MINIMUM_LENGTH + \
		ALWAYSON_PDU_SESSION_REQUESTED_MINIMUM_LENGTH + \
		SMPDUDN_REQUEST_CONTAINER_MINIMUM_LENGTH + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MINIMUM_LENGTH + \
0)

/* Maximum length macro. Formed by maximum length of each field */
#define PDU_SESSION_ESTABLISHMENT_REQUEST_MAXIMUM_LENGTH ( \
		EXTENDED_PROTOCOL_DISCRIMINATOR_MAXIMUM_LENGTH + \
		PDU_SESSION_IDENTITY_MAXIMUM_LENGTH + \
		PROCEDURE_TRANSACTION_IDENTITY_MAXIMUM_LENGTH + \
		MESSAGE_TYPE_MAXIMUM_LENGTH + \
		INTERGRITY_PROTECTION_MAXIMUM_DATA_RATE_MAXIMUM_LENGTH + \
		_PDU_SESSION_TYPE_MAXIMUM_LENGTH + \
		SSC_MODE_MAXIMUM_LENGTH + \
		_5GSM_CAPABILITY_MAXIMUM_LENGTH + \
		MAXIMUM_NUMBER_OF_SUPPORTED_PACKET_FILTERS_MAXIMUM_LENGTH + \
		ALWAYSON_PDU_SESSION_REQUESTED_MAXIMUM_LENGTH + \
		SMPDUDN_REQUEST_CONTAINER_MAXIMUM_LENGTH + \
		EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS_MAXIMUM_LENGTH + \
0)


#define PDU_SESSION_ESTABLISHMENT_REQUEST_PDU_SESSION_TYPE_IEI								0x90
#define PDU_SESSION_ESTABLISHMENT_REQUEST_SSC_MODE_IEI										0xA0
#define PDU_SESSION_ESTABLISHMENT_REQUEST__5GSM_CAPABILITY_IEI								0x28
#define PDU_SESSION_ESTABLISHMENT_REQUEST_MAXIMUM_NUMBER_OF_SUPPORTED_IEI					0x55
#define PDU_SESSION_ESTABLISHMENT_REQUEST_ALWAYSON_PDU_SESSION_REQUESTED_IEI				0xB0
#define PDU_SESSION_ESTABLISHMENT_REQUEST_SMPDUDN_REQUEST_CONTAINER_INFORMATION_IEI			0x39
#define PDU_SESSION_ESTABLISHMENT_REQUEST_E_P_C_O_IEI										0x7B

#define PDU_SESSION_ESTABLISHMENT_REQUEST_PDU_SESSION_TYPE_PRESENT 							(1<<0)
#define PDU_SESSION_ESTABLISHMENT_REQUEST_SSC_MODE_PRESENT 									(1<<1)
#define PDU_SESSION_ESTABLISHMENT_REQUEST__5GSM_CAPABILITY_PRESENT 							(1<<2)
#define PDU_SESSION_ESTABLISHMENT_REQUEST_MAXIMUM_NUMBER_OF_SUPPORTED_PRESENT 				(1<<3)
#define PDU_SESSION_ESTABLISHMENT_REQUEST_ALWAYSON_PDU_SESSION_REQUESTED_PRESENT 			(1<<4)
#define PDU_SESSION_ESTABLISHMENT_REQUEST_SMPDUDN_REQUEST_CONTAINER_INFORMATION_PRESENT 	(1<<5)
#define PDU_SESSION_ESTABLISHMENT_REQUEST_E_P_C_O_PRESENT 									(1<<6)


typedef struct pdu_session_establishment_request_msg_tag{
	ExtendedProtocolDiscriminator extendedprotocoldiscriminator;
	PDUSessionIdentity pdusessionidentity;
	ProcedureTransactionIdentity proceduretransactionidentity;
	MessageType messagetype;
	IntergrityProtectionMaximumDataRate intergrityprotectionmaximumdatarate;
	uint8_t presence;
	_PDUSessionType _pdusessiontype;
	SSCMode sscmode;
	_5GSMCapability _5gsmcapability;
	MaximumNumberOfSupportedPacketFilters maximumnumberofsupportedpacketfilters;
	AlwaysonPDUSessionRequested alwaysonpdusessionrequested;
	SMPDUDNRequestContainer smpdudnrequestcontainer;
	ExtendedProtocolConfigurationOptions extendedprotocolconfigurationoptions;
}pdu_session_establishment_request_msg;

int decode_pdu_session_establishment_request(pdu_session_establishment_request_msg *pdusessionestablishmentrequest, uint8_t *buffer, uint32_t len);
int encode_pdu_session_establishment_request(pdu_session_establishment_request_msg *pdusessionestablishmentrequest, uint8_t *buffer, uint32_t len);
