/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common2.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_SequenceOfitsAidSspList_H_
#define	_SequenceOfitsAidSspList_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct ItsAidSsp;

/* SequenceOfitsAidSspList */
typedef struct SequenceOfitsAidSspList {
	A_SEQUENCE_OF(struct ItsAidSsp) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SequenceOfitsAidSspList_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SequenceOfitsAidSspList;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "ItsAidSsp.h"

#endif	/* _SequenceOfitsAidSspList_H_ */
#include "asn_internal.h"