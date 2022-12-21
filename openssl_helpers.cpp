//****************************************************************************
//
// Copyright (c) ALTAP, spol. s r.o. All rights reserved.
//
// This is a part of the Altap Salamander SDK library.
//
// The SDK is provided "AS IS" and without warranty of any kind and 
// ALTAP EXPRESSLY DISCLAIMS ALL WARRANTIES, EXPRESS AND IMPLIED, INCLUDING,
// BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE and NON-INFRINGEMENT.
//
//****************************************************************************

#include <precomp.h>

#include "openssl_helpers.h"

#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/pkcs12.h>

// prints out a separator between certificates
void PrintSeparator(BIO *bio_out)
{
	BIO_printf(bio_out, "\n\n=======================================================================\n\n");
}


// static function taken from crypto/asn1/a_d2i_fp.c

#define HEADER_SIZE   8
#define ASN1_CHUNK_INITIAL_SIZE (16 * 1024)
int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb)
{
	BUF_MEM *b;
	unsigned char *p;
	int i;
	size_t want = HEADER_SIZE;
	uint32_t eos = 0;
	size_t off = 0;
	size_t len = 0;
	size_t diff;

	const unsigned char *q;
	long slen;
	int inf, tag, xclass;

	b = BUF_MEM_new();
	if (b == NULL) {
		ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
		return -1;
	}

	ERR_set_mark();
	for (;;) {
		diff = len - off;
		if (want >= diff) {
			want -= diff;

			if (len + want < len || !BUF_MEM_grow_clean(b, len + want)) {
				ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
				goto err;
			}
			i = BIO_read(in, &(b->data[len]), want);
			if (i < 0 && diff == 0) {
				ERR_raise(ERR_LIB_ASN1, ASN1_R_NOT_ENOUGH_DATA);
				goto err;
			}
			if (i > 0) {
				if (len + i < len) {
					ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
					goto err;
				}
				len += i;
			}
		}
		/* else data already loaded */

		p = (unsigned char *)&(b->data[off]);
		q = p;
		diff = len - off;
		if (diff == 0)
			goto err;
		inf = ASN1_get_object(&q, &slen, &tag, &xclass, diff);
		if (inf & 0x80) {
			unsigned long e;

			e = ERR_GET_REASON(ERR_peek_last_error());
			if (e != ASN1_R_TOO_LONG)
				goto err;
			ERR_pop_to_mark();
		}
		i = q - p;            /* header length */
		off += i;               /* end of data */

		if (inf & 1) {
			/* no data body so go round again */
			if (eos == UINT32_MAX) {
				ERR_raise(ERR_LIB_ASN1, ASN1_R_HEADER_TOO_LONG);
				goto err;
			}
			eos++;
			want = HEADER_SIZE;
		} else if (eos && (slen == 0) && (tag == V_ASN1_EOC)) {
			/* eos value, so go back and read another header */
			eos--;
			if (eos == 0)
				break;
			else
				want = HEADER_SIZE;
		} else {
			/* suck in slen bytes of data */
			want = slen;
			if (want > (len - off)) {
				size_t chunk_max = ASN1_CHUNK_INITIAL_SIZE;

				want -= (len - off);
				if (want > INT_MAX /* BIO_read takes an int length */  ||
					len + want < len) {
					ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
					goto err;
				}
				while (want > 0) {
					/*
					 * Read content in chunks of increasing size
					 * so we can return an error for EOF without
					 * having to allocate the entire content length
					 * in one go.
					 */
					size_t chunk = want > chunk_max ? chunk_max : want;

					if (!BUF_MEM_grow_clean(b, len + chunk)) {
						ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
						goto err;
					}
					want -= chunk;
					while (chunk > 0) {
						i = BIO_read(in, &(b->data[len]), chunk);
						if (i <= 0) {
							ERR_raise(ERR_LIB_ASN1, ASN1_R_NOT_ENOUGH_DATA);
							goto err;
						}
					/*
					 * This can't overflow because |len+want| didn't
					 * overflow.
					 */
						len += i;
						chunk -= i;
					}
					if (chunk_max < INT_MAX/2)
						chunk_max *= 2;
				}
			}
			if (off + slen < off) {
				ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
				goto err;
			}
			off += slen;
			if (eos == 0) {
				break;
			} else
				want = HEADER_SIZE;
		}
	}

	if (off > INT_MAX) {
		ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
		goto err;
	}

	*pb = b;
	return off;
 err:
	ERR_clear_last_mark();
	BUF_MEM_free(b);
	return -1;
}

// code taken from apps/pkcs12.c

int alg_print(BIO *bio_out, const X509_ALGOR *alg)
{
	int pbenid, aparamtype;
	const ASN1_OBJECT *aoid;
	const void *aparam;
	PBEPARAM *pbe = NULL;

	BIO_printf(bio_out, "\nAlgorithm:\n");

	X509_ALGOR_get0(&aoid, &aparamtype, &aparam, alg);

	pbenid = OBJ_obj2nid(aoid);

	BIO_printf(bio_out, "  Type: %s\n", OBJ_nid2ln(pbenid));

	/*
	 * If PBE algorithm is PBES2 decode algorithm parameters
	 * for additional details.
	 */
	if (pbenid == NID_pbes2) {
		PBE2PARAM *pbe2 = NULL;
		int encnid;
		if (aparamtype == V_ASN1_SEQUENCE)
			pbe2 = (PBE2PARAM*) ASN1_item_unpack((const ASN1_STRING*) aparam, ASN1_ITEM_rptr(PBE2PARAM));
		if (pbe2 == NULL) {
			//BIO_puts(bio_out, ", <unsupported parameters>");
			goto done;
		}
		X509_ALGOR_get0(&aoid, &aparamtype, &aparam, pbe2->keyfunc);
		pbenid = OBJ_obj2nid(aoid);
		BIO_printf(bio_out, "  Key Func: %s\n", OBJ_nid2ln(pbenid));
		X509_ALGOR_get0(&aoid, NULL, NULL, pbe2->encryption);
		encnid = OBJ_obj2nid(aoid);
		BIO_printf(bio_out, "  Encryption: %s\n", OBJ_nid2sn(encnid));
		/* If KDF is PBKDF2 decode parameters */
		if (pbenid == NID_id_pbkdf2) {
			PBKDF2PARAM *kdf = NULL;
			int prfnid;
			if (aparamtype == V_ASN1_SEQUENCE)
				kdf = (PBKDF2PARAM*) ASN1_item_unpack((const ASN1_STRING*) aparam, ASN1_ITEM_rptr(PBKDF2PARAM));
			if (kdf == NULL) {
				//BIO_puts(bio_out, ", <unsupported parameters>");
				goto done;
			}

			if (kdf->prf == NULL) {
				prfnid = NID_hmacWithSHA1;
			} else {
				X509_ALGOR_get0(&aoid, NULL, NULL, kdf->prf);
				prfnid = OBJ_obj2nid(aoid);
			}
			BIO_printf(bio_out, "  Iteration %ld\n  PRF %s\n",
					   ASN1_INTEGER_get(kdf->iter), OBJ_nid2sn(prfnid));
			PBKDF2PARAM_free(kdf);
#ifndef OPENSSL_NO_SCRYPT
		} else if (pbenid == NID_id_scrypt) {
			SCRYPT_PARAMS *kdf = NULL;

			if (aparamtype == V_ASN1_SEQUENCE)
				kdf = (SCRYPT_PARAMS*) ASN1_item_unpack((const ASN1_STRING*) aparam, ASN1_ITEM_rptr(SCRYPT_PARAMS));
			if (kdf == NULL) {
				//BIO_puts(bio_out, ", <unsupported parameters>");
				goto done;
			}
			BIO_printf(bio_out, "  Salt length: %d\n  Cost(N): %ld\n  "
					   "Block size(r): %ld\n  Parallelism(p): %ld\n",
					   ASN1_STRING_length(kdf->salt),
					   ASN1_INTEGER_get(kdf->costParameter),
					   ASN1_INTEGER_get(kdf->blockSize),
					   ASN1_INTEGER_get(kdf->parallelizationParameter));
			SCRYPT_PARAMS_free(kdf);
#endif
		}
		PBE2PARAM_free(pbe2);
	} else {
		if (aparamtype == V_ASN1_SEQUENCE)
			pbe = (PBEPARAM*) ASN1_item_unpack((const ASN1_STRING*) aparam, ASN1_ITEM_rptr(PBEPARAM));
		if (pbe == NULL) {
			//BIO_puts(bio_out, ", <unsupported parameters>");
			goto done;
		}
		BIO_printf(bio_out, "  Iteration %ld\n", ASN1_INTEGER_get(pbe->iter));
		PBEPARAM_free(pbe);
	}
 done:
	BIO_puts(bio_out, "\n");
	return 1;
}
