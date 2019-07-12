#include "hashtable.h"
#include "common_types.h"


struct gnb_description_s;

#define NGAP_TIMER_INACTIVE_ID   (-1)
#define NGAP_UE_CONTEXT_REL_COMP_TIMER 1

struct ngap_timer_t{
    long id;
    long sec;
};

// The current n2 state of the AMF relating to the specific gNB
enum amf_ng_gnb_state_s{
    NGAP_INIT,
    NGAP_RESETING,
    NGAP_READY,
    NGAP_SHUTDOWN    
};

enum ng_ue_state_s{
    NGAP_UE_INVALID_STATE,
    NGAP_UE_WAITING_CSR,
    NGAP_UE_HANDOVER,
    NGAP_UE_CONNECTED,
    NGAP_UE_WAITING_CRR    
};

typedef struct ue_description_s{
  struct gnb_description_s * gnb;
  enum ng_ue_state_s         ng_ue_state;
  ran_ue_ngap_id_t           ran_ue_ngap_id:24;
  amf_ue_ngap_id_t           amf_ue_ngap_id;
  sctp_stream_id_t           sctp_stream_recv;
  sctp_stream_id_t           sctp_stream_send;
  long outcome_response_timer_id;
  struct ngap_timer_t   ngap_ue_context_rel_timer;
}ue_description_t;


typedef struct gnb_description_s {

  enum amf_ng_gnb_state_s ng_state;         ///< State of the gNB specific NGAP association

  /** gNB related parameters **/
  /*@{*/
  char     gnb_name[150];      ///< Printable gNB Name
  uint32_t gnb_id;             ///< Unique gNB ID
  uint8_t  default_paging_drx; ///< Default paging DRX interval for gNB
  /*@}*/

  /** UE list for this gNB **/
  /*@{*/
  uint32_t nb_ue_associated; ///< Number of NAS associated UE on this gNB
  hash_table_ts_t  ue_coll; // contains ue_description_s, key is ue_description_s.?;
  /*@}*/

  /** SCTP stuff **/
  /*@{*/
  sctp_assoc_id_t  sctp_assoc_id;    ///< SCTP association id on this machine
  sctp_stream_id_t next_sctp_stream; ///< Next SCTP stream
  sctp_stream_id_t instreams;        ///< Number of streams avalaible on gNB -> AMF
  sctp_stream_id_t outstreams;       ///< Number of streams avalaible on AMF -> gNB
  /*@}*/
} gnb_description_t;

int ngap_amf_init(void);
gnb_description_t* ngap_is_gnb_assoc_id_in_list(const sctp_assoc_id_t sctp_assoc_id);
gnb_description_t* ngap_new_gnb(void);
ue_description_t* ngap_is_ue_gnb_id_in_list(gnb_description_t *gnb_ref, const ran_ue_ngap_id_t ran_ue_ngap_id);
ue_description_t* ngap_is_ue_amf_id_in_list(const amf_ue_ngap_id_t amf_ue_ngap_id);


ue_description_t* ngap_new_ue(const sctp_assoc_id_t sctp_assoc_id, ran_ue_ngap_id_t ran_ue_ngap_id);

void ngap_notified_new_ue_amf_ngap_id_association (
    const sctp_assoc_id_t  sctp_assoc_id,
    const ran_ue_ngap_id_t ran_ue_ngap_id,
    const amf_ue_ngap_id_t amf_ue_ngap_id);

