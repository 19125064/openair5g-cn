#include "intertask_interface.h"
#include "ngap_common.h"



int ngap_handle_new_association(sctp_new_peer_t *sctp_new_peer_p);

int ngap_handle_sctp_disconnection(const sctp_assoc_id_t assoc_id);


int ngap_amf_handle_ng_setup_request(const sctp_assoc_id_t assoc_id, const sctp_stream_id_t stream,
		Ngap_NGAP_PDU_t *pdu);
int ngap_amf_handle_ng_setup_failure(const sctp_assoc_id_t assoc_id, const sctp_stream_id_t stream,
		Ngap_NGAP_PDU_t *pdu);
int ngap_amf_handle_ng_initial_ue_message(const sctp_assoc_id_t assoc_id, const sctp_stream_id_t stream,
				Ngap_NGAP_PDU_t *pdu);

int ngap_amf_handle_ng_uplink_nas_transport(const sctp_assoc_id_t assoc_id, const sctp_stream_id_t stream,
				Ngap_NGAP_PDU_t *pdu);

