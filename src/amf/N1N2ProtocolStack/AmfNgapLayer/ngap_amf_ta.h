#ifndef FILE_NGAP_AMF_TA_SEEN               
#define FILE_NGAP_AMF_TA_SEEN               
  
enum {
  TA_LIST_UNKNOWN_TAC = -2,               
  TA_LIST_UNKNOWN_PLMN = -1,              
  TA_LIST_RET_OK = 0,                     
  TA_LIST_NO_MATCH = 0x1,
  TA_LIST_AT_LEAST_ONE_MATCH = 0x2,
  TA_LIST_COMPLETE_MATCH = 0x3,
};

int ngap_amf_compare_ta_lists(Ngap_SupportedTAList_t *ta_list);
  
#endif /* FILE_NGAP_AMF_TA_SEEN */   
