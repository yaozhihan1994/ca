/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_UnknownLongitude_H_
#define	_UnknownLongitude_H_


#include "asn_application.h"

/* Including external dependencies */
#include "OneEightyDegreeInt.h"

#ifdef __cplusplus
extern "C" {
#endif

/* UnknownLongitude */
typedef OneEightyDegreeInt_t	 UnknownLongitude_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UnknownLongitude;
asn_struct_free_f UnknownLongitude_free;
asn_struct_print_f UnknownLongitude_print;
asn_constr_check_f UnknownLongitude_constraint;
ber_type_decoder_f UnknownLongitude_decode_ber;
der_type_encoder_f UnknownLongitude_encode_der;
xer_type_decoder_f UnknownLongitude_decode_xer;
xer_type_encoder_f UnknownLongitude_encode_xer;
per_type_decoder_f UnknownLongitude_decode_uper;
per_type_encoder_f UnknownLongitude_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _UnknownLongitude_H_ */
#include "asn_internal.h"
