/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_PolygonalRegion_H_
#define	_PolygonalRegion_H_


#include "asn_application.h"

/* Including external dependencies */
#include "asn_SEQUENCE_OF.h"
#include "constr_SEQUENCE_OF.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct TwoDLocation;

/* PolygonalRegion */
typedef struct PolygonalRegion {
	A_SEQUENCE_OF(struct TwoDLocation) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PolygonalRegion_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PolygonalRegion;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "TwoDLocation.h"

#endif	/* _PolygonalRegion_H_ */
#include "asn_internal.h"
