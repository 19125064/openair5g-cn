#include "smMsgDef.h"
#include "PDUSessionEstablishmentRequest.h"
#include "PDUSessionEstablishmentAccept.h"
#include "PDUSessionEstablishmentReject.h"

#include "PDUSessionAuthenticationCommand.h"
#include "PDUSessionAuthenticationComplete.h"
#include "PDUSessionAuthenticationResult.h"

#include "PDUSessionModificationRequest.h"
#include "PDUSessionModificationReject.h"
#include "PDUSessionModificationComplete.h"
#include "PDUSessionModificationCommand.h"
#include "PDUSessionModificationCommandReject.h"

#include "PDUSessionReleaseRequest.h"
#include "PDUSessionReleaseReject.h"
#include "PDUSessionReleaseCommand.h"
#include "PDUSessionReleaseComplete.h"

#include "_5GSMStatus.h"

typedef struct {
  sm_msg_header_t header;
  union {
  pdu_session_establishment_request_msg pdu_session_establishment_request;
  pdu_session_establishment_accept_msg pdu_session_establishment_accept;
  pdu_session_establishment_reject_msg pdu_session_establishment_reject;

  pdu_session_authentication_command_msg pdu_session_authentication_command;
  pdu_session_authentication_complete_msg pdu_session_authentication_complete;
  pdu_session_authentication_result_msg pdu_session_authentication_result;

  pdu_session_modification_request_msg pdu_session_modification_request;
  pdu_session_modification_reject_msg pdu_session_modification_reject;
  pdu_session_modification_complete_msg pdu_session_modification_complete;
  pdu_session_modification_command_msg pdu_session_modification_command;
  pdu_session_modification_command_reject_msg pdu_session_modification_command_reject;

  pdu_session_release_request_msg pdu_session_release_request;
  pdu_session_release_reject_msg pdu_session_release_reject;
  pdu_session_release_command_msg pdu_session_release_command;
  pdu_session_release_complete_msg pdu_session_release_complete;

  _5gsm_status_msg _5gsm_status;
  } specific_msg;
}SM_msg;
