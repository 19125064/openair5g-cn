#include "common_types.h"
#include "sm_msg.h"
#include "log.h"
#include "TLVDecoder.h"
#include "TLVEncoder.h"
#include "log.h"


/****************************************************************************/
/****************  E X T E R N A L    D E F I N I T I O N S  ****************/
/****************************************************************************/

/****************************************************************************/
/*******************  L O C A L    D E F I N I T I O N S  *******************/
/****************************************************************************/

static int                              _fivegsm_msg_decode_header (
  sm_msg_header_t * header,
  const uint8_t * buffer,
  uint32_t len);
static int                              _fivegsm_msg_encode_header (
  const sm_msg_header_t * header,
  uint8_t * buffer,
  uint32_t len);

/****************************************************************************/
/******************  E X P O R T E D    F U N C T I O N S  ******************/
/****************************************************************************/

/****************************************************************************
 **                                                                        **
 ** Name:  sm_msg_decode()                                          **
 **                                                                        **
 ** Description: Decode EPS Session Management messages                    **
 **                                                                        **
 ** Inputs:  buffer:  Pointer to the buffer containing the ESM   **
 **       message                                    **
 **      len:   Number of bytes that should be decoded     **
 **    Others:  None                                       **
 **                                                                        **
 ** Outputs:   msg:   The ESM message structure to be filled     **
 **      Return:  The number of bytes in the buffer if data  **
 **       have been successfully decoded;            **
 **       A negative error code otherwise.           **
 **    Others:  None                                       **
 **                                                                        **
 ***************************************************************************/
int
sm_msg_decode (
  SM_msg * msg,
  uint8_t * buffer,
  uint32_t len)
{
  int                                     header_result = 0;
  int                                     decode_result = 0;
  uint8_t                                *buffer_log = buffer;
  uint32_t                                len_log = len;
  int                                     down_link = 0;
  //OAILOG_FUNC_IN (LOG_NAS);
  /*
   * First decode the ESM message header
   */
  header_result = _fivegsm_msg_decode_header (&msg->header, buffer, len);

  if (header_result < 0) {

    //OAILOG_ERROR (LOG_NAS, "ESM-MSG   - Failed to decode ESM message header " "(%d)\n", header_result);
    //OAILOG_FUNC_RETURN (LOG_NAS, header_result);
  }

  buffer += header_result;
  len -= header_result;

  printf("\ndukl esm message type %d\n",msg->header.message_type);

  switch (msg->header.message_type) {
	  case PDU_SESSION_ESTABLISHMENT_REQUEST:
	  	   decode_result = decode_pdu_session_establishment_request(&msg->specific_msg.pdu_session_establishment_request, buffer, len);
	  break;
      case PDU_SESSION_ESTABLISHMENT_ACCPET:
	  	   decode_result = decode_pdu_session_establishment_accept(&msg->specific_msg.pdu_session_establishment_accept, buffer, len);
	  break;
      case PDU_SESSION_ESTABLISHMENT_REJECT:
	  	   decode_result = decode_pdu_session_establishment_reject(&msg->specific_msg.pdu_session_establishment_reject, buffer, len);
	  break;
      case PDU_SESSION_AUTHENTICATION_COMMAND:
	  	   decode_result = decode_pdu_session_authentication_command(&msg->specific_msg.pdu_session_authentication_command, buffer, len);
	  break;
      case PDU_SESSION_AUTHENTICATION_COMPLETE:
	  	   decode_result = decode_pdu_session_authentication_complete(&msg->specific_msg.pdu_session_authentication_complete, buffer, len);
	  break;
      case PDU_SESSION_AUTHENTICATION_RESULT:
	  	   decode_result = decode_pdu_session_authentication_result(&msg->specific_msg.pdu_session_authentication_result, buffer, len);
	  break;
      case PDU_SESSION_MODIFICATION_REQUEST:
	  	   decode_result = decode_pdu_session_modification_request(&msg->specific_msg.pdu_session_modification_request, buffer, len);
	  break;
      case PDU_SESSION_MODIFICATION_REJECT:
	  	   decode_result = decode_pdu_session_modification_reject(&msg->specific_msg.pdu_session_modification_reject, buffer, len);
	  break;
      case PDU_SESSION_MODIFICATION_COMMAND:
	  	   decode_result = decode_pdu_session_modification_command(&msg->specific_msg.pdu_session_modification_command, buffer, len);
	  break;
      case PDU_SESSION_MODIFICATION_COMPLETE:
	  	   decode_result = decode_pdu_session_modification_complete(&msg->specific_msg.pdu_session_modification_complete, buffer, len);
	  break;
      case PDU_SESSION_MODIFICATION_COMMANDREJECT:
	  	   decode_result = decode_pdu_session_modification_command_reject(&msg->specific_msg.pdu_session_modification_command_reject, buffer, len);
	  break;
      case PDU_SESSION_RELEASE_REQUEST:
	  	   decode_result = decode_pdu_session_release_request(&msg->specific_msg.pdu_session_release_request, buffer, len);
	  break;
      case PDU_SESSION_RELEASE_REJECT:
	  	   decode_result = decode_pdu_session_release_reject(&msg->specific_msg.pdu_session_release_reject, buffer, len);
	  break;
      case PDU_SESSION_RELEASE_COMMAND:
	  	   decode_result = decode_pdu_session_release_command(&msg->specific_msg.pdu_session_release_command, buffer, len);
	  break;
      case PDU_SESSION_RELEASE_COMPLETE:
	  	   decode_result = decode_pdu_session_release_complete(&msg->specific_msg.pdu_session_release_complete, buffer, len);
	  break;
	  case _5GSM_STAUS:
	  	   decode_result = decode__5gsm_status(&msg->specific_msg._5gsm_status, buffer, len);
	  break;

	  default:
	    //OAILOG_ERROR (LOG_NAS, "SM-MSG   - Unexpected message type: 0x%x\n",msg->header.message_type);
	    decode_result = TLV_WRONG_MESSAGE_TYPE;
	    break;
  }

  if (decode_result < 0) {
    //OAILOG_ERROR (LOG_NAS, "SM-MSG   - Failed to decode L3 ESM message 0x%x " "(%u)\n", msg->header.message_type, decode_result);
    //OAILOG_FUNC_RETURN (LOG_NAS, decode_result);
  } else {
    /*
     * Message has been decoded and security header removed, handle it has a
plain message
     */
    //nas_itti_plain_msg ((char *)buffer_log, (nas_message_t *) msg, len_log, down_link);
  }


  //OAILOG_FUNC_RETURN (LOG_NAS, header_result + decode_result);
  return header_result + decode_result;
}

/****************************************************************************
 **                                                                        **
 ** Name:  esm_msg_encode()                                          **
 **                                                                        **
 ** Description: Encode EPS Session Management messages                    **
 **                                                                        **
 ** Inputs:  msg:   The ESM message structure to encode        **
 **      length:  Maximal capacity of the output buffer      **
 **    Others:  None                                       **
 **                                                                        **
 ** Outputs:   buffer:  Pointer to the encoded data buffer         **
 **      Return:  The number of bytes in the buffer if data  **
 **       have been successfully encoded;            **
 **       A negative error code otherwise.           **
 **    Others:  None                                       **
 **                                                                        **
 ***************************************************************************/
int
fivegsm_msg_encode (
  SM_msg * msg,
  uint8_t * buffer,
  uint32_t len)
{
  printf("fivegsm_msg_encode , start ----------------------\n");
  //OAILOG_FUNC_IN (LOG_NAS);
  int                                     header_result = 0;
  int                                     encode_result = 0;
  uint8_t                                *buffer_log = buffer;
  int                                     down_link = 1;
  /*
   * First encode the ESM message header
   */
  header_result = _fivegsm_msg_encode_header (&msg->header, buffer, len);

  if (header_result < 0) {
    //OAILOG_ERROR (LOG_NAS, "ESM-MSG   - Failed to encode ESM message header (%d)\n", header_result);
    //OAILOG_FUNC_RETURN (LOG_NAS, header_result);
  }

  //OAILOG_INFO (LOG_NAS, "ESM-MSG   - Encoded ESM message header " "(%d)\n", header_result);
  buffer += header_result;
  len -= header_result;

  switch (msg->header.message_type) {
      case PDU_SESSION_ESTABLISHMENT_REQUEST:
	  	   encode_result = encode_pdu_session_establishment_request(&msg->specific_msg.pdu_session_establishment_request, buffer, len);
	  break;
      case PDU_SESSION_ESTABLISHMENT_ACCPET:
	  	   encode_result = encode_pdu_session_establishment_accept(&msg->specific_msg.pdu_session_establishment_accept, buffer, len);
	  break;
      case PDU_SESSION_ESTABLISHMENT_REJECT:
	  	   encode_result = encode_pdu_session_establishment_reject(&msg->specific_msg.pdu_session_establishment_reject, buffer, len);
	  break;
      case PDU_SESSION_AUTHENTICATION_COMMAND:
	  	   encode_result = encode_pdu_session_authentication_command(&msg->specific_msg.pdu_session_authentication_command, buffer, len);
	  break;
      case PDU_SESSION_AUTHENTICATION_COMPLETE:
	  	   encode_result = encode_pdu_session_authentication_complete(&msg->specific_msg.pdu_session_authentication_complete, buffer, len);
	  break;
      case PDU_SESSION_AUTHENTICATION_RESULT:
	  	   encode_result = encode_pdu_session_authentication_result(&msg->specific_msg.pdu_session_authentication_result, buffer, len);
	  break;
      case PDU_SESSION_MODIFICATION_REQUEST:
	  	   encode_result = encode_pdu_session_modification_request(&msg->specific_msg.pdu_session_modification_request, buffer, len);
	  break;
      case PDU_SESSION_MODIFICATION_REJECT:
	  	   encode_result = encode_pdu_session_modification_reject(&msg->specific_msg.pdu_session_modification_reject, buffer, len);
	  break;
      case PDU_SESSION_MODIFICATION_COMMAND:
	  	   encode_result = encode_pdu_session_modification_command(&msg->specific_msg.pdu_session_modification_command, buffer, len);
	  break;
      case PDU_SESSION_MODIFICATION_COMPLETE:
	  	   encode_result = encode_pdu_session_modification_complete(&msg->specific_msg.pdu_session_modification_complete, buffer, len);
	  break;
      case PDU_SESSION_MODIFICATION_COMMANDREJECT:
	  	   encode_result = encode_pdu_session_modification_command_reject(&msg->specific_msg.pdu_session_modification_command_reject, buffer, len);
	  break;
      case PDU_SESSION_RELEASE_REQUEST:
	  	   encode_result = encode_pdu_session_release_request(&msg->specific_msg.pdu_session_release_request, buffer, len);
	  break;
      case PDU_SESSION_RELEASE_REJECT:
	  	   encode_result = encode_pdu_session_release_reject(&msg->specific_msg.pdu_session_release_reject, buffer, len);
	  break;
      case PDU_SESSION_RELEASE_COMMAND:
	  	   encode_result = encode_pdu_session_release_command(&msg->specific_msg.pdu_session_release_command, buffer, len);
	  break;
      case PDU_SESSION_RELEASE_COMPLETE:
	  	   encode_result = encode_pdu_session_release_complete(&msg->specific_msg.pdu_session_release_complete, buffer, len);
	  break;
	  case _5GSM_STAUS:
	  	   encode_result = encode__5gsm_status(&msg->specific_msg._5gsm_status, buffer, len);
	  break;

	  default:
	    //OAILOG_ERROR (LOG_NAS, "SM-MSG   -  message type: 0x%x\n", msg->header.message_type);
	    encode_result = TLV_WRONG_MESSAGE_TYPE;
	    break;
  }

  if (encode_result < 0) {
    //OAILOG_ERROR (LOG_NAS, "SM-MSG   - Failed to encode L3 ESM message 0x%x ""(%d)\n", msg->header.message_type, encode_result);
  } else {
    //nas_itti_plain_msg ((char *)buffer_log, (nas_message_t *) msg,
    //header_result + encode_result, down_link);
  }

 // OAILOG_FUNC_RETURN (LOG_NAS, header_result + encode_result);
    return header_result + encode_result;
}

/****************************************************************************/
/*********************  L O C A L    F U N C T I O N S  *********************/
/****************************************************************************/

/****************************************************************************
 **                                                                        **
 ** Name:  _esm_msg_decode_header()                                  **
 **                                                                        **
 ** Description: Decode header of EPS Mobility Management message.         **
 **    The protocol discriminator and the security header type   **
 **    have already been decoded.                                **
 **                                                                        **
 ** Inputs:  buffer:  Pointer to the buffer containing the ESM   **
 **       message                                    **
 **      len:   Number of bytes that should be decoded     **
 **    Others:  None                                       **
 **                                                                        **
 ** Outputs:   header:  The ESM message header to be filled        **
 **      Return:  The size of the header if data have been   **
 **       successfully decoded;                      **
 **       A negative error code otherwise.           **
 **    Others:  None                                       **
 **                                                                        **
 ***************************************************************************/
static int
_fivegsm_msg_decode_header (
  sm_msg_header_t * header,
  const uint8_t * buffer,
  uint32_t len)
{
  int                                     size = 0;

  /*
   * Check the buffer length
   */
  if (len < sizeof (sm_msg_header_t)) {
    return (TLV_BUFFER_TOO_SHORT);
  }

  /*
   * Decode the EPS bearer identity and the protocol discriminator
   */
  //DECODE_U8 (buffer + size, *(uint8_t *) (header), size);
  DECODE_U8(buffer + size, header->extended_protocol_discriminator, size);

  /*
   * Decode the procedure transaction identity
   */
  DECODE_U8(buffer + size, header->pdu_session_identity, size);

  /*
   * Decode the procedure transaction identity
   */
  DECODE_U8 (buffer + size, header->proeduer_transaction_identity, size);
  /*
   * Decode the message type
   */
  DECODE_U8 (buffer + size, header->message_type, size);

  /*
   * Check the protocol discriminator
   */
  if (header->extended_protocol_discriminator != FIVEGS_SESSION_MANAGEMENT_MESSAGES) {
    OAILOG_ERROR (LOG_NAS, "SM-MSG   - extended protocol discriminator: 0x%x\n", header->extended_protocol_discriminator);
    return (TLV_PROTOCOL_NOT_SUPPORTED);
  }

  return (size);
}

/****************************************************************************
 **                                                                        **
 ** Name:  _esm_msg_encode_header()                                  **
 **                                                                        **
 **    The protocol discriminator and the security header type   **
 **    have already been encoded.                                **
 **                                                                        **
 ** Inputs:  header:  The ESM message header to encode           **
 **      len:   Maximal capacity of the output buffer      **
 **    Others:  None                                       **
 **                                                                        **
 ** Outputs:   buffer:  Pointer to the encoded data buffer         **
 **      Return:  The number of bytes in the buffer if data  **
 **       have been successfully encoded;            **
 **       A negative error code otherwise.           **
 **    Others:  None                                       **
 **                                                                        **
 ***************************************************************************/
static int
_fivegsm_msg_encode_header (
  const sm_msg_header_t * header,
  uint8_t * buffer,
  uint32_t len)
{
  int                                     size = 0;

  /*
   * Check the buffer length
   */
  if (len < sizeof (sm_msg_header_t)) {
    //OAILOG_ERROR (LOG_NAS, "SM-MSG   - buffer too short\n");
    return (TLV_BUFFER_TOO_SHORT);
  }
  /*
   * Check the protocol discriminator
   */
  else if (header->extended_protocol_discriminator != FIVEGS_SESSION_MANAGEMENT_MESSAGES) {
    //OAILOG_ERROR (LOG_NAS, "SM-MSG   - Unexpected protocol discriminator: 0x%x\n", header->extended_protocol_discriminator);
    return (TLV_PROTOCOL_NOT_SUPPORTED);
  }

  /*
   * Encode the EPS bearer identity and the protocol discriminator
   */
  //ENCODE_U8 (buffer + size, *(uint8_t *) (header), size);
  ENCODE_U8 (buffer + size, header->extended_protocol_discriminator , size);
  /*
   * Encode the procedure session identity
   */
  ENCODE_U8 (buffer + size, header->pdu_session_identity, size);

  /*
   * Encode the procedure transaction identity
   */
  ENCODE_U8 (buffer + size, header->proeduer_transaction_identity, size);
  /*
   * Encode the message type
   */
  ENCODE_U8 (buffer + size, header->message_type, size);

  return (size);
}
