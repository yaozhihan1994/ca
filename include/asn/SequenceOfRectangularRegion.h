/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_SequenceOfRectangularRegion_H_
#define	_SequenceOfRectangularRegion_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct RectangularRegion;

/* SequenceOfRectangularRegion */
typedef struct SequenceOfRectangularRegion {
	A_SEQUENCE_OF(struct RectangularRegion) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SequenceOfRectangularRegion_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SequenceOfRectangularRegion;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "RectangularRegion.h"

#endif	/* _SequenceOfRectangularRegion_H_ */
#include "asn_internal.h"
