/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common2.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_SequenceOfUint16_H_
#define	_SequenceOfUint16_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Uint16.h"
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SequenceOfUint16 */
typedef struct SequenceOfUint16 {
	A_SEQUENCE_OF(Uint16_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SequenceOfUint16_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SequenceOfUint16;

#ifdef __cplusplus
}
#endif

#endif	/* _SequenceOfUint16_H_ */
#include "asn_internal.h"