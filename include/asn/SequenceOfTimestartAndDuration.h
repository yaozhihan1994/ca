/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common2.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#ifndef	_SequenceOfTimestartAndDuration_H_
#define	_SequenceOfTimestartAndDuration_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Time32.h"
#include "Duration.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SequenceOfTimestartAndDuration */
typedef struct SequenceOfTimestartAndDuration {
	Time32_t	 startValidity;
	Duration_t	 duration;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} SequenceOfTimestartAndDuration_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_SequenceOfTimestartAndDuration;

#ifdef __cplusplus
}
#endif

#endif	/* _SequenceOfTimestartAndDuration_H_ */
#include "asn_internal.h"
