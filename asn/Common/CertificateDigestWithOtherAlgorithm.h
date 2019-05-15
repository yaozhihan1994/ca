/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_CertificateDigestWithOtherAlgorithm_H_
#define	_CertificateDigestWithOtherAlgorithm_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PublicKeyAlgorithm.h"
#include "HashedId8.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* CertificateDigestWithOtherAlgorithm */
typedef struct CertificateDigestWithOtherAlgorithm {
	PublicKeyAlgorithm_t	 algorithm;
	HashedId8_t	 digest;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CertificateDigestWithOtherAlgorithm_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CertificateDigestWithOtherAlgorithm;

#ifdef __cplusplus
}
#endif

#endif	/* _CertificateDigestWithOtherAlgorithm_H_ */
#include "asn_internal.h"
