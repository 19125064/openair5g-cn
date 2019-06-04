#define NGAP_NAS_DL_DATA_REQ(mSGpTR)        (mSGpTR)->ittiMsg.ngap_nas_dl_data_req

typedef struct itti_ngap_dl_nas_data_req_s {
  amf_ue_ngap_id_t  amf_ue_ngap_id;
  ran_ue_ngap_id_t  ran_ue_ngap_id:24;
  bstring           nas_msg;            /* Downlink NAS message             */
} itti_ngap_nas_dl_data_req_t;
