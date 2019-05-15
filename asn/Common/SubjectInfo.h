/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_SubjectInfo_H_
#define	_SubjectInfo_H_


#include "asn_application.h"

/* Including external dependencies */
#include "SubjectType.h"
#include "OCTET_STRING.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SubjectInfo */
typedef struct SubjectInfo {
	SubjectType_t	 subjectType;
	OCTET_STRING_t	 subjectName;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SubjectInfo_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SubjectInfo;

#ifdef __cplusplus
}
#endif

#endif	/* _SubjectInfo_H_ */
#include "asn_internal.h"
