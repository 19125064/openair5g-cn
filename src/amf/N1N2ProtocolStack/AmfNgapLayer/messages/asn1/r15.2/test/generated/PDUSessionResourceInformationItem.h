/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "NGAP-IEs.asn"
 * 	`asn1c -D ./generated/`
 */

#ifndef	_PDUSessionResourceInformationItem_H_
#define	_PDUSessionResourceInformationItem_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PDUSessionID.h"
#include "QosFlowInformationList.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct DRBsToQosFlowsMappingList;
struct ProtocolExtensionContainer;

/* PDUSessionResourceInformationItem */
typedef struct PDUSessionResourceInformationItem {
	PDUSessionID_t	 pDUSessionID;
	QosFlowInformationList_t	 qosFlowInformationList;
	struct DRBsToQosFlowsMappingList	*dRBsToQosFlowsMappingList	/* OPTIONAL */;
	struct ProtocolExtensionContainer	*iE_Extensions	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PDUSessionResourceInformationItem_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PDUSessionResourceInformationItem;
extern asn_SEQUENCE_specifics_t asn_SPC_PDUSessionResourceInformationItem_specs_1;
extern asn_TYPE_member_t asn_MBR_PDUSessionResourceInformationItem_1[4];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "DRBsToQosFlowsMappingList.h"
#include "ProtocolExtensionContainer.h"

#endif	/* _PDUSessionResourceInformationItem_H_ */
#include <asn_internal.h>