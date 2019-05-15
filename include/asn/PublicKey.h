/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_PublicKey_H_
#define	_PublicKey_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OCTET_STRING.h"
#include "EncryptKey.h"
#include "constr_CHOICE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PublicKey_PR {
	PublicKey_PR_NOTHING,	/* No components present */
	PublicKey_PR_signKey,
	PublicKey_PR_encKey,
	/* Extensions may appear below */
	
} PublicKey_PR;

/* PublicKey */
typedef struct PublicKey {
	PublicKey_PR present;
	union PublicKey_u {
		OCTET_STRING_t	 signKey;
		EncryptKey_t	 encKey;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PublicKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PublicKey;

#ifdef __cplusplus
}
#endif

#endif	/* _PublicKey_H_ */
#include "asn_internal.h"
