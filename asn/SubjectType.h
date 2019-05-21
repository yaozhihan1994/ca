/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common2.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_SubjectType_H_
#define	_SubjectType_H_


#include "asn_application.h"

/* Including external dependencies */
#include "NativeEnumerated.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum SubjectType {
	SubjectType_enrollmentCredential	= 0,
	SubjectType_authorizationTicket	= 1,
	SubjectType_authorizationAuthority	= 2,
	SubjectType_enrollmentAuthority	= 3,
	SubjectType_rootCa	= 4,
	SubjectType_crlSigner	= 5
} e_SubjectType;

/* SubjectType */
typedef long	 SubjectType_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SubjectType;
asn_struct_free_f SubjectType_free;
asn_struct_print_f SubjectType_print;
asn_constr_check_f SubjectType_constraint;
ber_type_decoder_f SubjectType_decode_ber;
der_type_encoder_f SubjectType_encode_der;
xer_type_decoder_f SubjectType_decode_xer;
xer_type_encoder_f SubjectType_encode_xer;
per_type_decoder_f SubjectType_decode_uper;
per_type_encoder_f SubjectType_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _SubjectType_H_ */
#include "asn_internal.h"