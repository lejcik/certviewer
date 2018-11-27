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

#include "precomp.h"
#include "certdump.h"
#include "openssl_helpers.h"

BOOL errHandler(BIO *out)
{
	auto ret = ERR_GET_REASON(ERR_peek_last_error());
	if (ret != PEM_R_NO_START_LINE)
	{
		BIO_printf(out, "Failed to load certificate file\n");
		return FALSE;
	}

	return TRUE;
}

BOOL ParseObjectType(BIO *bio_in, char *buf, size_t buflen)
{
	// PEM object type data
	char *name = NULL, *header = NULL;
	unsigned char *data = NULL;
	long len;

	// read PEM object header
	auto ret = PEM_read_bio(bio_in, &name, &header, &data, &len);

	// save object type name
	if (ret)
		strcpy_s(buf, buflen, name);
	else
		*buf = 0;

	if (name != NULL)
		OPENSSL_free(name);
	if (header != NULL)
		OPENSSL_free(header);
	if (data != NULL)
		OPENSSL_free(data);

	return ret != 0;
}

BOOL ParseCertificateFileAsPEM(BIO *bio_in, BIO *bio_out)
{
	char name[64];

	// ensure that we are at the beginning of file
	BIO_seek(bio_in, 0);

	while (true)
	{
		// remember position in the stream
		const auto pos = BIO_tell(bio_in);

		// read PEM object header
		if (!ParseObjectType(bio_in, name, sizeof(name)))
		{
			const auto ret = ERR_GET_REASON(ERR_peek_last_error());
			if (ret == PEM_R_NO_START_LINE)
			{
				// no PEM object read, return error
				if (pos == 0)
					return FALSE;

				// end of file reached
				break;
			}

			return FALSE;
		}

		// print separator between certificates
		if (pos)
			PrintSeparator(bio_out);

		BIO_printf(bio_out, "Object type: %s\n", name);
		BIO_printf(bio_out, "Format: PEM\n\n");

		// seek back to read PEM object by type
		BIO_seek(bio_in, pos);

		// print out PEM object info by type
		if (strcmp(name, PEM_STRING_X509) == 0 ||
			strcmp(name, PEM_STRING_X509_OLD) == 0)
		{
			auto obj = PEM_read_bio_X509(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			X509_print(bio_out, obj);
			X509_free(obj);
		}
/*		else if (strcmp(name, PEM_STRING_X509_PAIR) == 0)
		{
			auto obj = PEM_read_bio_X509_CERT_PAIR(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			// TODO: unclear
			// X509_CERT_PAIR_it(bio_out, obj);
			X509_CERT_PAIR_free(obj);
		}
*/		else if (strcmp(name, PEM_STRING_X509_TRUSTED) == 0)
		{
			auto obj = PEM_read_bio_X509_AUX(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			X509_print(bio_out, obj);
			X509_free(obj);
		}
		else if (strcmp(name, PEM_STRING_X509_REQ) == 0 ||
				 strcmp(name, PEM_STRING_X509_REQ_OLD) == 0)
		{
			auto obj = PEM_read_bio_X509_REQ(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			X509_REQ_print(bio_out, obj);
			X509_REQ_free(obj);
		}
		else if (strcmp(name, PEM_STRING_X509_CRL) == 0)
		{
			auto obj = PEM_read_bio_X509_CRL(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			X509_CRL_print(bio_out, obj);
			X509_CRL_free(obj);
		}
		else if (strcmp(name, PEM_STRING_EVP_PKEY) == 0 ||
				 strcmp(name, PEM_STRING_PUBLIC) == 0)
		{
			auto obj = PEM_read_bio_PUBKEY(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			EVP_PKEY_print_public(bio_out, obj, 0, NULL);
			EVP_PKEY_print_private(bio_out, obj, 0, NULL);
			EVP_PKEY_print_params(bio_out, obj, 0, NULL);
			EVP_PKEY_free(obj);
		}
		else if (strcmp(name, PEM_STRING_RSA) == 0)
		{
			auto obj = PEM_read_bio_RSAPrivateKey(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			RSA_print(bio_out, obj, 0);
			RSA_free(obj);
		}
		else if (strcmp(name, PEM_STRING_RSA_PUBLIC) == 0)
		{
			auto obj = PEM_read_bio_RSAPublicKey(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			RSA_print(bio_out, obj, 0);
			RSA_free(obj);
		}
		else if (strcmp(name, PEM_STRING_DSA) == 0)
		{
			auto obj = PEM_read_bio_DSAPrivateKey(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			DSA_print(bio_out, obj, 0);
			DSA_free(obj);
		}
		else if (strcmp(name, PEM_STRING_DSA_PUBLIC) == 0)
		{
			auto obj = PEM_read_bio_DSA_PUBKEY(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			DSA_print(bio_out, obj, 0);
			DSA_free(obj);
		}
		else if (strcmp(name, PEM_STRING_PKCS7) == 0 ||
				 strcmp(name, PEM_STRING_PKCS7_SIGNED) == 0)
		{
			auto obj = PEM_read_bio_PKCS7(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			PKCS7_print_certs(bio_out, obj);
			PKCS7_free(obj);
		}
		else if (strcmp(name, PEM_STRING_PKCS8) == 0)
		{
			auto obj = PEM_read_bio_PKCS8(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			// X509_SIG_it(bio_out, obj, 0, NULL);
			X509_SIG_free(obj);
		}
		else if (strcmp(name, PEM_STRING_PKCS8INF) == 0)
		{
			auto obj = PEM_read_bio_PKCS8_PRIV_KEY_INFO(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			//PKCS8_PRIV_KEY_INFO_it(bio_out, obj, 0, NULL);

			// TODO: print out private key info
			BIO_printf(bio_out, "encrypted private key\n");
			PKCS8_PRIV_KEY_INFO_free(obj);
		}
		// ...
		else if (strcmp(name, PEM_STRING_CMS) == 0)
		{
			auto obj = PEM_read_bio_CMS(bio_in, NULL, 0, NULL);
			if (!obj)
				return errHandler(bio_out);
			CMS_ContentInfo_print_ctx(bio_out, obj, 0, NULL);
			CMS_ContentInfo_free(obj);
		}
		else
		{
			BIO_printf(bio_out, "cannot decode unsupported PEM object\n");
			return FALSE;
		}
	}

	// file parsed successfully
	return TRUE;
}

BOOL ParseCertificateFileAsDER(BIO *bio_in, BIO *bio_out)
{
	// ensure that we are at the beginning of file
	BIO_seek(bio_in, 0);

	// remember position in the stream
	const auto pos = BIO_tell(bio_in);

	// verify that file is in DER format
	BUF_MEM *b = NULL;
	auto len = asn1_d2i_read_bio(bio_in, &b);
	if (len <= 0)
		return FALSE;
	if (!b)
		return FALSE;
	BUF_MEM_free(b);

	// print certificate info if it matches one of the supported formats:

	BIO_seek(bio_in, pos);
	auto x509 = d2i_X509_bio(bio_in, NULL);
	if (x509)
	{
		BIO_printf(bio_out, "Object type: %s\n", "X509 Certificate");
		BIO_printf(bio_out, "Format: DER\n\n");

		X509_print(bio_out, x509);
		X509_free(x509);
		return TRUE;
	}

	BIO_seek(bio_in, pos);
	auto x509crl = d2i_X509_CRL_bio(bio_in, NULL);
	if (x509crl)
	{
		BIO_printf(bio_out, "Object type: %s\n", "X509 CRL");
		BIO_printf(bio_out, "Format: DER\n\n");

		X509_CRL_print(bio_out, x509crl);
		X509_CRL_free(x509crl);
		return TRUE;
	}

	BIO_seek(bio_in, pos);
	auto x509req = d2i_X509_REQ_bio(bio_in, NULL);
	if (x509req)
	{
		BIO_printf(bio_out, "Object type: %s\n", "X509 Certificate Request");
		BIO_printf(bio_out, "Format: DER\n\n");

		X509_REQ_print(bio_out, x509req);
		X509_REQ_free(x509req);
		return TRUE;
	}

	BIO_seek(bio_in, pos);
	auto pkcs7 = d2i_PKCS7_bio(bio_in, NULL);
	if (pkcs7)
	{
		BIO_printf(bio_out, "Object type: %s\n", "PKCS7");
		BIO_printf(bio_out, "Format: DER\n\n");

		PKCS7_print_certs(bio_out, pkcs7);
		PKCS7_free(pkcs7);
		return TRUE;
	}

	BIO_seek(bio_in, pos);
	const char *rsa_type = "RSA Private Key";
	auto rsa = d2i_RSAPrivateKey_bio(bio_in, NULL);
	if (!rsa)
	{
		rsa_type = "RSA Public Key";
		rsa = d2i_RSAPublicKey_bio(bio_in, NULL);
	}
	if (rsa)
	{
		BIO_printf(bio_out, "Object type: %s\n", rsa_type);
		BIO_printf(bio_out, "Format: DER\n\n");

		RSA_print(bio_out, rsa, 0);
		RSA_free(rsa);
		return TRUE;
	}

	return FALSE;
}

BOOL ParseCertificateFile(BIO *bio_in, BIO *bio_out)
{
	// try out to parse PEM format at first,
	// then the binary one
	if (ParseCertificateFileAsPEM(bio_in, bio_out) ||
		ParseCertificateFileAsDER(bio_in, bio_out))
	{
		return TRUE;
	}

	return FALSE;
}

BOOL DumpCertificate(const char *certFile, FILE *out)
{
	BOOL ret = FALSE;
	BIO *bio_in = NULL;
	BIO *bio_out = NULL;

	// TODO: open certificate as a binary file, some systems
	//       are sensitive on line endings, but on Windows
	//       it looks it works well

	// open file by name
	bio_in = BIO_new_file(certFile, "rb");
	if (!bio_in)
		goto cleanup;

	// initialize output stream
	bio_out = BIO_new_fp(out, BIO_NOCLOSE);
	if (!bio_out)
		goto cleanup;

	// print out file info
	ret = ParseCertificateFile(bio_in, bio_out);

cleanup:
	if (bio_out)
		BIO_free(bio_out);
	if (bio_in)
		BIO_free(bio_in);

	return ret;
}
