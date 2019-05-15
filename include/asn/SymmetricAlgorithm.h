/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_SymmetricAlgorithm_H_
#define	_SymmetricAlgorithm_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeEnumerated.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SymmetricAlgorithm {
	SymmetricAlgorithm_sgdsm4ecb	= 1,
	SymmetricAlgorithm_sgdsm4cbc	= 2,
	SymmetricAlgorithm_sgdsm4cfb	= 3,
	SymmetricAlgorithm_sgdsm4ofb	= 4
	/*
	 * Enumeration is extensible
	 */
} e_SymmetricAlgorithm;

/* SymmetricAlgorithm */
typedef long	 SymmetricAlgorithm_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SymmetricAlgorithm;
asn_struct_free_f SymmetricAlgorithm_free;
asn_struct_print_f SymmetricAlgorithm_print;
asn_constr_check_f SymmetricAlgorithm_constraint;
ber_type_decoder_f SymmetricAlgorithm_decode_ber;
der_type_encoder_f SymmetricAlgorithm_encode_der;
xer_type_decoder_f SymmetricAlgorithm_decode_xer;
xer_type_encoder_f SymmetricAlgorithm_encode_xer;
per_type_decoder_f SymmetricAlgorithm_decode_uper;
per_type_encoder_f SymmetricAlgorithm_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _SymmetricAlgorithm_H_ */
#include "asn_internal.h"
