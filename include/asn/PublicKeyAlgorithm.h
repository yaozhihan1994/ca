/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_PublicKeyAlgorithm_H_
#define	_PublicKeyAlgorithm_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeEnumerated.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum PublicKeyAlgorithm {
	PublicKeyAlgorithm_sgdsm3sm2	= 2,
	PublicKeyAlgorithm_sgdsm2	= 3
	/*
	 * Enumeration is extensible
	 */
} e_PublicKeyAlgorithm;

/* PublicKeyAlgorithm */
typedef long	 PublicKeyAlgorithm_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PublicKeyAlgorithm;
asn_struct_free_f PublicKeyAlgorithm_free;
asn_struct_print_f PublicKeyAlgorithm_print;
asn_constr_check_f PublicKeyAlgorithm_constraint;
ber_type_decoder_f PublicKeyAlgorithm_decode_ber;
der_type_encoder_f PublicKeyAlgorithm_encode_der;
xer_type_decoder_f PublicKeyAlgorithm_decode_xer;
xer_type_encoder_f PublicKeyAlgorithm_encode_xer;
per_type_decoder_f PublicKeyAlgorithm_decode_uper;
per_type_encoder_f PublicKeyAlgorithm_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _PublicKeyAlgorithm_H_ */
#include "asn_internal.h"
