/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_TwoDLocation_H_
#define	_TwoDLocation_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Latitude.h"
#include "Longitude.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* TwoDLocation */
typedef struct TwoDLocation {
	Latitude_t	 latitude;
	Longitude_t	 longitude;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} TwoDLocation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_TwoDLocation;

#ifdef __cplusplus
}
#endif

#endif	/* _TwoDLocation_H_ */
#include "asn_internal.h"
