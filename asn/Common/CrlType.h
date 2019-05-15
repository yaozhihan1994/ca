/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_CrlType_H_
#define	_CrlType_H_


#include "asn_application.h"

/* Including external dependencies */
#include "HashedId10.h"
#include "IdAndDate.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum CrlType_PR {
	CrlType_PR_NOTHING,	/* No components present */
	CrlType_PR_idOnly,
	CrlType_PR_idAndExpiry,
	/* Extensions may appear below */
	
} CrlType_PR;

/* CrlType */
typedef struct CrlType {
	CrlType_PR present;
	union CrlType_u {
		HashedId10_t	 idOnly;
		IdAndDate_t	 idAndExpiry;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CrlType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CrlType;

#ifdef __cplusplus
}
#endif

#endif	/* _CrlType_H_ */
#include "asn_internal.h"
