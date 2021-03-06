/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common2.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#include "ValidityRestriction.h"

static asn_per_constraints_t asn_PER_type_ValidityRestriction_constr_1 GCC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  2,  2,  0,  3 }	/* (0..3,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_ValidityRestriction_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ValidityRestriction, choice.timeEnd),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Time32,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timeEnd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ValidityRestriction, choice.timeStartAndEnd),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SequenceOfTimeStartAndEnd,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timeStartAndEnd"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ValidityRestriction, choice.timestartAndDuration),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SequenceOfTimestartAndDuration,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"timestartAndDuration"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ValidityRestriction, choice.region),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_GeographicRegion,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"region"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_ValidityRestriction_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* timeEnd */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* timeStartAndEnd */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* timestartAndDuration */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 } /* region */
};
static asn_CHOICE_specifics_t asn_SPC_ValidityRestriction_specs_1 = {
	sizeof(struct ValidityRestriction),
	offsetof(struct ValidityRestriction, _asn_ctx),
	offsetof(struct ValidityRestriction, present),
	sizeof(((struct ValidityRestriction *)0)->present),
	asn_MAP_ValidityRestriction_tag2el_1,
	4,	/* Count of tags in the map */
	0,
	4	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_ValidityRestriction = {
	"ValidityRestriction",
	"ValidityRestriction",
	CHOICE_free,
	CHOICE_print,
	CHOICE_constraint,
	CHOICE_decode_ber,
	CHOICE_encode_der,
	CHOICE_decode_xer,
	CHOICE_encode_xer,
	CHOICE_decode_uper,
	CHOICE_encode_uper,
	CHOICE_outmost_tag,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	&asn_PER_type_ValidityRestriction_constr_1,
	asn_MBR_ValidityRestriction_1,
	4,	/* Elements count */
	&asn_SPC_ValidityRestriction_specs_1	/* Additional specs */
};

