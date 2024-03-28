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

#include "openssl_helpers.h"

#include <openssl/err.h>
#include <openssl/buffer.h>

// prints out formatted message for the given error code
void PrintUnpackError(BIO *out)
{
    // firstly, handle the known error messages
    const auto err = ERR_peek_last_error();
    if (ERR_GET_LIB(err) == ERR_LIB_PKCS12 &&
        ERR_GET_REASON(err) == PKCS12_R_PKCS12_CIPHERFINAL_ERROR)
    {
        BIO_printf(out, "Invalid password.\n");
        return;
    }
    if (ERR_GET_LIB(err) == ERR_LIB_PKCS12 &&
        ERR_GET_REASON(err) == PKCS12_R_DECODE_ERROR)
    {
        BIO_printf(out, "Decode error.\n");
        return;
    }
    else if (ERR_GET_REASON(err) == EVP_R_UNSUPPORTED_ALGORITHM ||
             ERR_GET_REASON(err) == ERR_R_UNSUPPORTED)
    {
        BIO_printf(out, "Unsupported algorithm.\n");
        return;
    }

    // print function name
    const char *func = NULL;
    ERR_peek_error_func(&func);
    if (func)
        BIO_printf(out, "%s: ", func);

    // print error message
    const char *msg;
    if (!ERR_SYSTEM_ERROR(err) && (msg = ERR_reason_error_string(err)) != NULL)
        BIO_printf(out, "%s\n", msg);
    else
        BIO_printf(out, "reason(%lu).\n", ERR_GET_REASON(err));
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

// functions taken from apps/pkcs12.c

int dump_certs_keys_p12(BIO *out, const PKCS12 *p12,
                        const char *pass, int passlen, int options,
                        char *pempass, const EVP_CIPHER *enc);
int dump_certs_pkeys_bags(BIO *out, const STACK_OF(PKCS12_SAFEBAG) *bags,
                          const char *pass, int passlen, int options,
                          char *pempass, const EVP_CIPHER *enc);
int dump_certs_pkeys_bag(BIO *out, const PKCS12_SAFEBAG *bags,
                         const char *pass, int passlen,
                         int options, char *pempass, const EVP_CIPHER *enc);
void print_attribute(BIO *out, const ASN1_TYPE *av);
int print_attribs(BIO *out, const STACK_OF(X509_ATTRIBUTE) *attrlst,
                  const char *name);
void hex_prin(BIO *out, unsigned char *buf, int len);
static int alg_print(BIO *out, const X509_ALGOR *alg);

int dump_certs_keys_p12(BIO *out, const PKCS12 *p12, const char *pass,
                        int passlen, int options, char *pempass,
                        const EVP_CIPHER *enc)
{
    STACK_OF(PKCS7) *asafes = NULL;
    int i, bagnid;
    int ret = 0;
    PKCS7 *p7;

    ERR_clear_error();
    if ((asafes = PKCS12_unpack_authsafes(p12)) == NULL) {
        BIO_printf(out, "!! ERROR: Failed to unpack PKCS12 data bags! ");
        PrintUnpackError(out);
        return 0;
    }
    if (sk_PKCS7_num(asafes) == 0) {
        BIO_printf(out, "!! WARNING: No PKCS12 data bag found!");
        goto err;
    }
	BIO_printf(out, "PKCS12 data bags count: %d\n\n", sk_PKCS7_num(asafes));

    for (i = 0; i < sk_PKCS7_num(asafes); i++) {
        STACK_OF(PKCS12_SAFEBAG) *bags;

        p7 = sk_PKCS7_value(asafes, i);
        bagnid = OBJ_obj2nid(p7->type);
        if (bagnid == NID_pkcs7_data) {
            bags = PKCS12_unpack_p7data(p7);
            // if (options & INFO)
                BIO_printf(out, "PKCS7 Data\n");
            if (!bags) {
                BIO_printf(out, "    !! ERROR: No data present!\n");
                BIO_printf(out, "\n");
                continue;
            }
        } else if (bagnid == NID_pkcs7_encrypted) {
            // if (options & INFO) {
                BIO_printf(out, "PKCS7 Encrypted data: ");
                if (p7->d.encrypted == NULL) {
                    BIO_printf(out, "<no data>\n");
                } else {
                    alg_print(out, p7->d.encrypted->enc_data->algorithm);
                }
            // }
            ERR_clear_error();
            bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
            if (!bags) {
                BIO_printf(out, "    !! ERROR: Failed to unpack data! ");
                PrintUnpackError(out);
                BIO_printf(out, "\n");
                continue;
            }
        } else {
            continue;
        }
        if (bags == NULL)
            goto err;
        if (!dump_certs_pkeys_bags(out, bags, pass, passlen,
                                   options, pempass, enc)) {
            sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
            goto err;
        }
        sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
        bags = NULL;
        BIO_printf(out, "\n");
    }
    ret = 1;

 err:
    sk_PKCS7_pop_free(asafes, PKCS7_free);
    return ret;
}

int dump_certs_pkeys_bags(BIO *out, const STACK_OF(PKCS12_SAFEBAG) *bags,
                          const char *pass, int passlen, int options,
                          char *pempass, const EVP_CIPHER *enc)
{
    int i;
    for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) {
        if (!dump_certs_pkeys_bag(out,
                                  sk_PKCS12_SAFEBAG_value(bags, i),
                                  pass, passlen, options, pempass, enc))
            return 0;
    }
    return 1;
}

int dump_certs_pkeys_bag(BIO *out, const PKCS12_SAFEBAG *bag,
                         const char *pass, int passlen, int options,
                         char *pempass, const EVP_CIPHER *enc)
{
    EVP_PKEY *pkey;
    PKCS8_PRIV_KEY_INFO *p8;
    const PKCS8_PRIV_KEY_INFO *p8c;
    X509 *x509;
    const STACK_OF(X509_ATTRIBUTE) *attrs;
    int ret = 0;

    attrs = PKCS12_SAFEBAG_get0_attrs(bag);

    switch (PKCS12_SAFEBAG_get_nid(bag)) {
    case NID_keyBag:
        // if (options & INFO)
            BIO_printf(out, "Key bag\n");
        // if (options & NOKEYS)
        //     return 1;
        print_attribs(out, attrs, "Bag Attributes");
        p8c = PKCS12_SAFEBAG_get0_p8inf(bag);
        if ((pkey = EVP_PKCS82PKEY(p8c)) == NULL) {
            BIO_printf(out, "    !! ERROR: Private Key not present!\n");
            // return 0;
            return 1;
        }
        print_attribs(out, PKCS8_pkey_get0_attrs(p8c), "Key Attributes");
        // ret = PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
        EVP_PKEY_print_private(out, pkey, 0, NULL);
        EVP_PKEY_free(pkey);
        // break;
        return 1;

    case NID_pkcs8ShroudedKeyBag:
        /* if (options & INFO) */ {
            const X509_SIG *tp8;
            const X509_ALGOR *tp8alg;

            BIO_printf(out, "Shrouded Keybag: ");
            tp8 = PKCS12_SAFEBAG_get0_pkcs8(bag);
            X509_SIG_get0(tp8, &tp8alg, NULL);
            alg_print(out, tp8alg);
        }
        // if (options & NOKEYS)
        //     return 1;
        print_attribs(out, attrs, "Bag Attributes");
        ERR_clear_error();
        if ((p8 = PKCS12_decrypt_skey(bag, pass, passlen)) == NULL) {
            BIO_printf(out, "    !! ERROR: Failed to decrypt Private Key! ");
            PrintUnpackError(out);
            // return 0;
            return 1;
        }
        if ((pkey = EVP_PKCS82PKEY(p8)) == NULL) {
            BIO_printf(out, "    !! ERROR: Private Key not present!\n");
            PKCS8_PRIV_KEY_INFO_free(p8);
            // return 0;
            return 1;
        }
        print_attribs(out, PKCS8_pkey_get0_attrs(p8), "Key Attributes");
        PKCS8_PRIV_KEY_INFO_free(p8);
        // ret = PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
        EVP_PKEY_print_private(out, pkey, 0, NULL);
        EVP_PKEY_free(pkey);
        // break;
        return 1;

    case NID_certBag:
        // if (options & INFO)
            BIO_printf(out, "Certificate bag\n");
        // if (options & NOCERTS)
        //     return 1;
        // if (PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID)) {
        //     if (options & CACERTS)
        //         return 1;
        // } else if (options & CLCERTS)
        //     return 1;
        print_attribs(out, attrs, "Bag Attributes");
        if (PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate)
            return 1;
        if ((x509 = PKCS12_SAFEBAG_get1_cert(bag)) == NULL) {
            BIO_printf(out, "    !! ERROR: Certificate not present!\n");
            // return 0;
            return 1;
        }
        // dump_cert_text(out, x509);
        // ret = PEM_write_bio_X509(out, x509);
        X509_print(out, x509);
        X509_free(x509);
        // break;
        return 1;

    case NID_secretBag:
        // if (options & INFO)
            BIO_printf(out, "Secret bag\n");
        print_attribs(out, attrs, "Bag Attributes");
        BIO_printf(out, "Bag Type: ");
        i2a_ASN1_OBJECT(out, PKCS12_SAFEBAG_get0_bag_type(bag));
        BIO_printf(out, "\nBag Value: ");
        print_attribute(out, PKCS12_SAFEBAG_get0_bag_obj(bag));
        return 1;

    case NID_safeContentsBag:
        // if (options & INFO)
            BIO_printf(out, "Safe Contents bag\n");
        print_attribs(out, attrs, "Bag Attributes");
        return dump_certs_pkeys_bags(out, PKCS12_SAFEBAG_get0_safes(bag),
                                     pass, passlen, options, pempass, enc);

    default:
        BIO_printf(out, "Warning unsupported bag type: ");
        i2a_ASN1_OBJECT(out, PKCS12_SAFEBAG_get0_type(bag));
        BIO_printf(out, "\n");
        return 1;
    }
    return ret;
}

static int alg_print(BIO *out, const X509_ALGOR *alg)
{
    int pbenid, aparamtype;
    const ASN1_OBJECT *aoid;
    const void *aparam;
    PBEPARAM *pbe = NULL;

    X509_ALGOR_get0(&aoid, &aparamtype, &aparam, alg);

    pbenid = OBJ_obj2nid(aoid);

    BIO_printf(out, "%s", OBJ_nid2ln(pbenid));

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
            BIO_puts(out, ", <unsupported parameters>");
            goto done;
        }
        X509_ALGOR_get0(&aoid, &aparamtype, &aparam, pbe2->keyfunc);
        pbenid = OBJ_obj2nid(aoid);
        X509_ALGOR_get0(&aoid, NULL, NULL, pbe2->encryption);
        encnid = OBJ_obj2nid(aoid);
        BIO_printf(out, ", %s, %s", OBJ_nid2ln(pbenid),
                   OBJ_nid2sn(encnid));
        /* If KDF is PBKDF2 decode parameters */
        if (pbenid == NID_id_pbkdf2) {
            PBKDF2PARAM *kdf = NULL;
            int prfnid;
            if (aparamtype == V_ASN1_SEQUENCE)
                kdf = (PBKDF2PARAM*) ASN1_item_unpack((const ASN1_STRING*) aparam, ASN1_ITEM_rptr(PBKDF2PARAM));
            if (kdf == NULL) {
                BIO_puts(out, ", <unsupported parameters>");
                goto done;
            }

            if (kdf->prf == NULL) {
                prfnid = NID_hmacWithSHA1;
            } else {
                X509_ALGOR_get0(&aoid, NULL, NULL, kdf->prf);
                prfnid = OBJ_obj2nid(aoid);
            }
            BIO_printf(out, ", Iteration %ld, PRF %s",
                       ASN1_INTEGER_get(kdf->iter), OBJ_nid2sn(prfnid));
            PBKDF2PARAM_free(kdf);
#ifndef OPENSSL_NO_SCRYPT
        } else if (pbenid == NID_id_scrypt) {
            SCRYPT_PARAMS *kdf = NULL;

            if (aparamtype == V_ASN1_SEQUENCE)
                kdf = (SCRYPT_PARAMS*) ASN1_item_unpack((const ASN1_STRING*) aparam, ASN1_ITEM_rptr(SCRYPT_PARAMS));
            if (kdf == NULL) {
                BIO_puts(out, ", <unsupported parameters>");
                goto done;
            }
            BIO_printf(out, ", Salt length: %d, Cost(N): %ld, "
                       "Block size(r): %ld, Parallelism(p): %ld",
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
            BIO_puts(out, ", <unsupported parameters>");
            goto done;
        }
        BIO_printf(out, ", Iteration %ld", ASN1_INTEGER_get(pbe->iter));
        PBEPARAM_free(pbe);
    }
 done:
    BIO_puts(out, "\n");
    return 1;
}

/* Generalised x509 attribute value print */

void print_attribute(BIO *out, const ASN1_TYPE *av)
{
    char *value;
    const char *ln;
    char objbuf[80];

    switch (av->type) {
    case V_ASN1_BMPSTRING:
        value = OPENSSL_uni2asc(av->value.bmpstring->data,
                                av->value.bmpstring->length);
        BIO_printf(out, "%s\n", value);
        OPENSSL_free(value);
        break;

    case V_ASN1_UTF8STRING:
        BIO_printf(out, "%.*s\n", av->value.utf8string->length,
                   av->value.utf8string->data);
        break;

    case V_ASN1_OCTET_STRING:
        hex_prin(out, av->value.octet_string->data,
                 av->value.octet_string->length);
        BIO_printf(out, "\n");
        break;

    case V_ASN1_BIT_STRING:
        hex_prin(out, av->value.bit_string->data,
                 av->value.bit_string->length);
        BIO_printf(out, "\n");
        break;

    case V_ASN1_OBJECT:
        ln = OBJ_nid2ln(OBJ_obj2nid(av->value.object));
        if (!ln)
            ln = "";
        OBJ_obj2txt(objbuf, sizeof(objbuf), av->value.object, 1);
        BIO_printf(out, "%s (%s)", ln, objbuf);
        BIO_printf(out, "\n");
        break;

    default:
        BIO_printf(out, "<Unsupported tag %d>\n", av->type);
        break;
    }
}

/* Generalised attribute print: handle PKCS#8 and bag attributes */

int print_attribs(BIO *out, const STACK_OF(X509_ATTRIBUTE) *attrlst,
                  const char *name)
{
    X509_ATTRIBUTE *attr;
    ASN1_TYPE *av;
    int i, j, attr_nid;
    if (!attrlst) {
        BIO_printf(out, "%s: <No Attributes>\n", name);
        return 1;
    }
    if (!sk_X509_ATTRIBUTE_num(attrlst)) {
        BIO_printf(out, "%s: <Empty Attributes>\n", name);
        return 1;
    }
    BIO_printf(out, "%s\n", name);
    for (i = 0; i < sk_X509_ATTRIBUTE_num(attrlst); i++) {
        ASN1_OBJECT *attr_obj;
        attr = sk_X509_ATTRIBUTE_value(attrlst, i);
        attr_obj = X509_ATTRIBUTE_get0_object(attr);
        attr_nid = OBJ_obj2nid(attr_obj);
        BIO_printf(out, "    ");
        if (attr_nid == NID_undef) {
            i2a_ASN1_OBJECT(out, attr_obj);
            BIO_printf(out, ": ");
        } else {
            BIO_printf(out, "%s: ", OBJ_nid2ln(attr_nid));
        }

        if (X509_ATTRIBUTE_count(attr)) {
            for (j = 0; j < X509_ATTRIBUTE_count(attr); j++)
            {
                av = X509_ATTRIBUTE_get0_type(attr, j);
                print_attribute(out, av);
            }
        } else {
            BIO_printf(out, "<No Values>\n");
        }
    }
    return 1;
}

void hex_prin(BIO *out, unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; i++)
        BIO_printf(out, "%02X ", buf[i]);
}
