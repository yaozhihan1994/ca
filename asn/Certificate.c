/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Common"
 * 	found in "Common2.asn"
 * 	`asn1c -gen-PER -fincludes-quoted`
 */

#include "Certificate.h"

static asn_TYPE_member_t asn_MBR_Certificate_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Certificate, version),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Uint8,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"version"
		},
	{ ATF_POINTER, 0, offsetof(struct Certificate, signerInfo),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_SignerInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"signerInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Certificate, subjectInfo),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SubjectInfo,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"subjectInfo"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Certificate, subjectAttributes),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_SubjectAttribute,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"subjectAttributes"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Certificate, validityRestrictions),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ValidityRestriction,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"validityRestrictions"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Certificate, signature),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Signature,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"signature"
		},
};
static const ber_tlv_tag_t asn_DEF_Certificate_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Certificate_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* version */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* signerInfo */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* subjectInfo */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* subjectAttributes */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* validityRestrictions */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* signature */
};
static asn_SEQUENCE_specifics_t asn_SPC_Certificate_specs_1 = {
	sizeof(struct Certificate),
	offsetof(struct Certificate, _asn_ctx),
	asn_MAP_Certificate_tag2el_1,
	6,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_Certificate = {
	"Certificate",
	"Certificate",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_Certificate_tags_1,
	sizeof(asn_DEF_Certificate_tags_1)
		/sizeof(asn_DEF_Certificate_tags_1[0]), /* 1 */
	asn_DEF_Certificate_tags_1,	/* Same as above */
	sizeof(asn_DEF_Certificate_tags_1)
		/sizeof(asn_DEF_Certificate_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_Certificate_1,
	6,	/* Elements count */
	&asn_SPC_Certificate_specs_1	/* Additional specs */
};

