/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common2.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_CircularRegion_H_
#define	_CircularRegion_H_


#include "asn_application.h"

/* Including external dependencies */
#include "TwoDLocation.h"
#include "Uint16.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CircularRegion */
typedef struct CircularRegion {
	TwoDLocation_t	 center;
	Uint16_t	 radius;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CircularRegion_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CircularRegion;

#ifdef __cplusplus
}
#endif

#endif	/* _CircularRegion_H_ */
#include "asn_internal.h"