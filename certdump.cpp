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

#include "certdump.h"
#include "openssl_helpers.h"
#include <openssl/decoder.h>
#include <openssl/ssl.h>
#include <openssl/ts.h>
#include <openssl/ocsp.h>
#include <string>

struct PwdHandlerData
{
	PasswordCallback &callback;
	bool pwdProvided{false}; // true if password was provided by user, false otherwise

	PwdHandlerData(PasswordCallback &cb) : callback{cb}
	{}
};

void PrintSeparator(BIO* bio_out)
{
	BIO_printf(bio_out, "\n\n=======================================================================\n\n");
}

bool ErrorHandler(BIO *out)
{
	auto ret = ERR_GET_REASON(ERR_peek_last_error());
	if (ret != PEM_R_NO_START_LINE)
	{
		BIO_printf(out, "Failed to load certificate file\n");
		return false;
	}

	return true;
}

int PasswordHandler(char *buf, int size, int /*rwflag*/, void *u)
{
	if (!u)
		return -1;
	auto data = reinterpret_cast<PwdHandlerData*>(u);
	auto ret = std::invoke(data->callback, buf, size);
	if (ret != -1)
		data->pwdProvided = true;
	return ret;
}

void PrintCertHeader(BIO *bio_out, const char *objtype, const char *format)
{
	BIO_printf(bio_out, "Object type: %s\n", objtype);
	BIO_printf(bio_out, "Format: %s\n\n", format);
}

void PrintPrivateKeyInfo(BIO *bio_out, EVP_PKEY *pkey, bool pwdProtected)
{
	if (pwdProtected)
		BIO_printf(bio_out, "NOTE: private key is password protected!\n\n");
	EVP_PKEY_print_private(bio_out, pkey, 0, NULL);
}

void PrintSslSessionParams(BIO *bio_out, SSL_SESSION *ssl)
{
	SSL_SESSION_print(bio_out, ssl);
	BIO_printf(bio_out, "\n\nPeer certificate for the SSL session:\n\n");
	auto peer = SSL_SESSION_get0_peer(ssl);
	if (peer)
		X509_print(bio_out, peer);
	else
		BIO_printf(bio_out, "  No certificate present\n");
}

bool ParsePemObjectType(BIO *bio_in, char *buf, size_t buflen)
{
	// PEM object type data
	char *name = NULL, *header = NULL;
	unsigned char *data = NULL;
	long len;

	// read PEM object header
	auto ret = PEM_read_bio(bio_in, &name, &header, &data, &len);

	// save object type name
	if (ret)
#ifdef _WIN32
		strcpy_s(buf, buflen, name);
#else
	{
		strncpy(buf, name, buflen);
		buf[buflen - 1] = 0;
	}
#endif
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

bool ParseCertificateFileAsPEM(BIO *bio_in, BIO *bio_out, PasswordCallback &callback)
{
	char name[64];

	// ensure that we are at the beginning of file
	BIO_seek(bio_in, 0);

	while (true)
	{
		// remember position in the stream
		const auto pos = BIO_tell(bio_in);

		// read PEM object header
		if (!ParsePemObjectType(bio_in, name, sizeof(name)))
		{
			const auto ret = ERR_GET_REASON(ERR_peek_last_error());
			if (ret == PEM_R_NO_START_LINE)
			{
				// no PEM object read, return error
				if (pos == 0)
					return false;

				// end of file reached
				break;
			}

			return false;
		}

		// print separator between certificates
		if (pos)
			PrintSeparator(bio_out);

		PrintCertHeader(bio_out, name, "PEM");

		// seek back to read PEM object by type
		BIO_seek(bio_in, pos);

		// print out PEM object info by type
		if (strcmp(name, PEM_STRING_X509) == 0 ||
			strcmp(name, PEM_STRING_X509_OLD) == 0)
		{
			auto obj = PEM_read_bio_X509(bio_in, NULL, NULL, NULL);
			if (!obj)
				return ErrorHandler(bio_out);
			X509_print(bio_out, obj);
			X509_free(obj);
		}
		else if (strcmp(name, PEM_STRING_X509_TRUSTED) == 0)
		{
			auto obj = PEM_read_bio_X509_AUX(bio_in, NULL, NULL, NULL);
			if (!obj)
				return ErrorHandler(bio_out);
			X509_print(bio_out, obj);
			X509_free(obj);
		}
		else if (strcmp(name, PEM_STRING_X509_REQ) == 0 ||
				 strcmp(name, PEM_STRING_X509_REQ_OLD) == 0)
		{
			auto obj = PEM_read_bio_X509_REQ(bio_in, NULL, NULL, NULL);
			if (!obj)
				return ErrorHandler(bio_out);
			X509_REQ_print(bio_out, obj);
			X509_REQ_free(obj);
		}
		else if (strcmp(name, PEM_STRING_X509_CRL) == 0)
		{
			auto obj = PEM_read_bio_X509_CRL(bio_in, NULL, NULL, NULL);
			if (!obj)
				return ErrorHandler(bio_out);
			X509_CRL_print(bio_out, obj);
			X509_CRL_free(obj);
		}
		else if (strcmp(name, PEM_STRING_PUBLIC) == 0 ||
				 strcmp(name, PEM_STRING_RSA_PUBLIC) == 0 ||
				 strcmp(name, PEM_STRING_DSA_PUBLIC) == 0)
		{
			auto obj = PEM_read_bio_PUBKEY(bio_in, NULL, NULL, NULL);
			if (!obj)
				return ErrorHandler(bio_out);

			EVP_PKEY_print_public(bio_out, obj, 0, NULL);
			EVP_PKEY_free(obj);
		}
		else if (strcmp(name, PEM_STRING_EVP_PKEY) == 0 ||
				 strcmp(name, PEM_STRING_RSA) == 0 ||
				 strcmp(name, PEM_STRING_DSA) == 0 ||
				 strcmp(name, PEM_STRING_PKCS8INF) == 0 ||
				 strcmp(name, PEM_STRING_ECPRIVATEKEY) == 0)
		{
			PwdHandlerData data(callback);
			auto obj = PEM_read_bio_PrivateKey(bio_in, NULL, PasswordHandler, &data);
			if (!obj)
				return ErrorHandler(bio_out);

			PrintPrivateKeyInfo(bio_out, obj, data.pwdProvided);
			EVP_PKEY_free(obj);
		}
		else if (strcmp(name, PEM_STRING_PKCS7) == 0 ||
				 strcmp(name, PEM_STRING_PKCS7_SIGNED) == 0)
		{
			auto obj = PEM_read_bio_PKCS7(bio_in, NULL, NULL, NULL);
			if (!obj)
				return ErrorHandler(bio_out);
			PKCS7_print_ctx(bio_out, obj, 0, NULL);
			PKCS7_free(obj);
		}
		else if (strcmp(name, PEM_STRING_PKCS8) == 0)
		{
			bool pwdProvided = false;
			auto p8inf = PEM_read_bio_PKCS8_PRIV_KEY_INFO(bio_in, NULL, NULL, NULL);
			if (!p8inf)
			{
				// private key is encrypted
				BIO_seek(bio_in, pos);
				auto p8 = PEM_read_bio_PKCS8(bio_in, NULL, NULL, NULL);
				if (!p8)
					return ErrorHandler(bio_out);
				// firstly try empty password
				char password[PEM_BUFSIZE] = {0};
				p8inf = PKCS8_decrypt(p8, password, 0);
				if (!p8inf)
				{
					// need password, ask user to provide it
					auto ret = std::invoke(callback, password, static_cast<int>(sizeof(password)));
					if (ret != -1)
						p8inf = PKCS8_decrypt(p8, password, ret);
				}
				X509_SIG_free(p8);
				OPENSSL_cleanse(password, sizeof(password));
				pwdProvided = true;
			}
			if (!p8inf)
				return false;

			auto pkey = EVP_PKCS82PKEY(p8inf);
			PKCS8_PRIV_KEY_INFO_free(p8inf);
			if (!pkey)
				return false;
			PrintPrivateKeyInfo(bio_out, pkey, pwdProvided);
			EVP_PKEY_free(pkey);
		}
		else if (strcmp(name, PEM_STRING_DHPARAMS) == 0 ||
				 strcmp(name, PEM_STRING_DHXPARAMS) == 0 ||
				 strcmp(name, PEM_STRING_DSAPARAMS) == 0 ||
				 strcmp(name, PEM_STRING_ECPARAMETERS) == 0)
		{
			auto obj = PEM_read_bio_Parameters(bio_in, NULL);
			if (!obj)
				return ErrorHandler(bio_out);

			EVP_PKEY_print_params(bio_out, obj, 0, NULL);
			EVP_PKEY_free(obj);
		}
		else if (strcmp(name, PEM_STRING_SSL_SESSION) == 0)
		{
			auto obj = PEM_read_bio_SSL_SESSION(bio_in, NULL, NULL, NULL);
			if (!obj)
				return ErrorHandler(bio_out);
			PrintSslSessionParams(bio_out, obj);
			SSL_SESSION_free(obj);
		}
#if 0
		else if (strcmp(name, PEM_STRING_ECDSA_PUBLIC) == 0)
		{
			// NOTE: this object seems not to be supported
		}
		else if (strcmp(name, PEM_STRING_PARAMETERS) == 0)
		{
			// NOTE: this object seems not to be supported
		}
#endif
		else if (strcmp(name, PEM_STRING_CMS) == 0)
		{
			auto obj = PEM_read_bio_CMS(bio_in, NULL, NULL, NULL);
			if (!obj)
				return ErrorHandler(bio_out);
			CMS_ContentInfo_print_ctx(bio_out, obj, 0, NULL);
			CMS_ContentInfo_free(obj);
		}
		else
		{
			BIO_printf(bio_out, "cannot decode unsupported PEM object\n");
			return false;
		}
	}

	// file parsed successfully
	return true;
}

EVP_PKEY *Get_KeyParams_bio(BIO *bio_in)
{
	// all types for d2i_KeyParams(type, ...)
	static const int types[] =
	{
		EVP_PKEY_RSA,
		EVP_PKEY_RSA2,
		EVP_PKEY_RSA_PSS,
		EVP_PKEY_DSA,
		EVP_PKEY_DSA1,
		EVP_PKEY_DSA2,
		EVP_PKEY_DSA3,
		EVP_PKEY_DSA4,
		EVP_PKEY_DH,
		EVP_PKEY_DHX,
		EVP_PKEY_EC,
		EVP_PKEY_SM2,
		EVP_PKEY_HMAC,
		EVP_PKEY_CMAC,
		EVP_PKEY_SCRYPT,
		EVP_PKEY_TLS1_PRF,
		EVP_PKEY_HKDF,
		EVP_PKEY_POLY1305,
		EVP_PKEY_SIPHASH,
		EVP_PKEY_X25519,
		EVP_PKEY_ED25519,
		EVP_PKEY_X448,
		EVP_PKEY_ED448
	};

	BUF_MEM *b = NULL;
	const auto len = asn1_d2i_read_bio(bio_in, &b);
	if (len < 0)
		return NULL;

	EVP_PKEY *ret = NULL;
	for (auto type : types)
	{
		const auto *p = (unsigned char *) b->data;
		ret = d2i_KeyParams(type, NULL, &p, len);
		if (ret != NULL)
			break;
	}

	BUF_MEM_free(b);
	return ret;
}

bool ParseCertificateFileAsDER(BIO *bio_in, BIO *bio_out, PasswordCallback &callback)
{
	static const char FORMAT[] = "DER";

	// ensure that we are at the beginning of file
	BIO_seek(bio_in, 0);

	// remember position in the stream
	const auto pos = BIO_tell(bio_in);

	// verify that file is in DER format
	BUF_MEM *b = NULL;
	auto len = asn1_d2i_read_bio(bio_in, &b);
	if (len <= 0 || !b)
		return false;
	BUF_MEM_free(b);

	// print certificate info if it matches one of the supported formats:

	// X509
	BIO_seek(bio_in, pos);
	auto x509 = d2i_X509_bio(bio_in, NULL);
	if (x509)
	{
		PrintCertHeader(bio_out, "X509 Certificate", FORMAT);

		X509_print(bio_out, x509);
		X509_free(x509);
		return true;
	}

	// X509_CRL
	BIO_seek(bio_in, pos);
	auto x509crl = d2i_X509_CRL_bio(bio_in, NULL);
	if (x509crl)
	{
		PrintCertHeader(bio_out, "X509 CRL", FORMAT);

		X509_CRL_print(bio_out, x509crl);
		X509_CRL_free(x509crl);
		return true;
	}

	// X509_REQ
	BIO_seek(bio_in, pos);
	auto x509req = d2i_X509_REQ_bio(bio_in, NULL);
	if (x509req)
	{
		PrintCertHeader(bio_out, "X509 Certificate Request", FORMAT);

		X509_REQ_print(bio_out, x509req);
		X509_REQ_free(x509req);
		return true;
	}

	// PKCS7
	BIO_seek(bio_in, pos);
	auto pkcs7 = d2i_PKCS7_bio(bio_in, NULL);
	if (pkcs7)
	{
		PrintCertHeader(bio_out, "PKCS7", FORMAT);

		PKCS7_print_ctx(bio_out, pkcs7, 0, NULL);
		PKCS7_free(pkcs7);
		return true;
	}

	// EVP_PKEY -> PrivateKey
	BIO_seek(bio_in, pos);
	const char *obj_type = " Private Key";
	auto obj = d2i_PrivateKey_bio(bio_in, NULL);
	if (obj)
	{
		auto type = EVP_PKEY_get0_type_name(obj);
		const auto type_str = std::string(type) + obj_type;
		PrintCertHeader(bio_out, type_str.c_str(), FORMAT);

		EVP_PKEY_print_private(bio_out, obj, 0, NULL);
		EVP_PKEY_free(obj);
		return true;
	}

	// EVP_PKEY -> PublicKey
	BIO_seek(bio_in, pos);
	obj_type = " Public Key";
	obj = d2i_PUBKEY_bio(bio_in, NULL);
	if (obj)
	{
		auto type = EVP_PKEY_get0_type_name(obj);
		const auto type_str = std::string(type) + obj_type;
		PrintCertHeader(bio_out, type_str.c_str(), FORMAT);

		EVP_PKEY_print_public(bio_out, obj, 0, NULL);
		EVP_PKEY_free(obj);
		return true;
	}

	// EVP_PKEY -> Parameters
	BIO_seek(bio_in, pos);
	obj_type = " Parameters";
	obj = Get_KeyParams_bio(bio_in);
	if (obj)
	{
		auto type = EVP_PKEY_get0_type_name(obj);
		const auto type_str = std::string(type) + obj_type;
		PrintCertHeader(bio_out, type_str.c_str(), FORMAT);

		EVP_PKEY_print_params(bio_out, obj, 0, NULL);
		EVP_PKEY_free(obj);
		return true;
	}

	// PKCS8 -> EVP_PKEY
	bool pwdProvided = false;
	BIO_seek(bio_in, pos);
	auto p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(bio_in, NULL);
	if (!p8inf)
	{
		// private key may be encrypted
		BIO_seek(bio_in, pos);
		auto p8 = d2i_PKCS8_bio(bio_in, NULL);
		if (p8)
		{
			// firstly try empty password
			char password[PEM_BUFSIZE] = {0};
			p8inf = PKCS8_decrypt(p8, password, 0);
			if (!p8inf)
			{
				// need password, ask user to provide it
				auto ret = std::invoke(callback, password, static_cast<int>(sizeof(password)));
				if (ret != -1)
					p8inf = PKCS8_decrypt(p8, password, ret);
			}
			X509_SIG_free(p8);
			OPENSSL_cleanse(password, sizeof(password));
			pwdProvided = true;
		}
	}
	if (p8inf)
	{
		auto pkey = EVP_PKCS82PKEY(p8inf);
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		if (!pkey)
			return false;
		PrintCertHeader(bio_out, "Encrypted Private Key", FORMAT);
		PrintPrivateKeyInfo(bio_out, pkey, pwdProvided);
		EVP_PKEY_free(pkey);
		return true;
	}

	// PKCS12
	BIO_seek(bio_in, pos);
	auto p12 = d2i_PKCS12_bio(bio_in, NULL);
	if (p12)
	{
		PrintCertHeader(bio_out, "PKCS#12 Encrypted Certificate", FORMAT);

		if (PKCS12_mac_present(p12))
		{
			// code in this block is taken from apps/pkcs12.c
			const ASN1_INTEGER *tmaciter;
			const X509_ALGOR *macalgid;
			const ASN1_OBJECT *macobj;
			const ASN1_OCTET_STRING *tmac;
			const ASN1_OCTET_STRING *tsalt;

			PKCS12_get0_mac(&tmac, &macalgid, &tsalt, &tmaciter, p12);
			/* current hash algorithms do not use parameters so extract just name,
			   in future alg_print() may be needed */
			X509_ALGOR_get0(&macobj, NULL, NULL, macalgid);
			BIO_puts(bio_out, "MAC: ");
			i2a_ASN1_OBJECT(bio_out, macobj);
			BIO_printf(bio_out, ", Iteration %ld\n",
					   tmaciter != NULL ? ASN1_INTEGER_get(tmaciter) : 1L);
			BIO_printf(bio_out, "MAC length: %ld, salt length: %ld\n",
					   tmac != NULL ? ASN1_STRING_length(tmac) : 0L,
					   tsalt != NULL ? ASN1_STRING_length(tsalt) : 0L);
		}
		else
		{
			// NOTE: unlikely, MAC should be always present, even it's optional!
			BIO_puts(bio_out, "MAC: <not present>\n");
			BIO_puts(bio_out, "Certificate file may be corrupted!\n");
			return true;
		}

		// try to verify mac with empty password
		char password[PEM_BUFSIZE] = {0};
		bool mac_verified = false;
		if (PKCS12_verify_mac(p12, password, -1))
			mac_verified = true;
		else
		{
			auto ret = std::invoke(callback, password, static_cast<int>(sizeof(password)));
			if (ret != -1 && PKCS12_verify_mac(p12, password, -1))
				mac_verified = true;
		}
		BIO_printf(bio_out, "MAC %s\n\n", mac_verified ? "verified OK" : "verify error! Invalid password.");

		dump_certs_keys_p12(bio_out, p12, password, -1, 0, NULL, NULL);
		PKCS12_free(p12);
		OPENSSL_cleanse(password, sizeof(password));
		return true;
	}

	// SSL_SESSION
	BIO_seek(bio_in, pos);
	auto ssl = d2i_SSL_SESSION_bio(bio_in, NULL);
	if (ssl)
	{
		PrintCertHeader(bio_out, "SSL Session Parameters", FORMAT);

		PrintSslSessionParams(bio_out, ssl);
		SSL_SESSION_free(ssl);
		return true;
	}

	// CMS
	BIO_seek(bio_in, pos);
	auto cms = d2i_CMS_bio(bio_in, NULL);
	if (cms)
	{
		// NOTE: DER format of CMS file is identical with PKCS7 one,
		//       so it may be opened with d2i_PKCS7_bio()
		PrintCertHeader(bio_out, "CMS", FORMAT);

		CMS_ContentInfo_print_ctx(bio_out, cms, 0, NULL);
		CMS_ContentInfo_free(cms);
		return true;
	}

	// TS_REQ
	BIO_seek(bio_in, pos);
	auto ts_req = d2i_TS_REQ_bio(bio_in, NULL);
	if (ts_req)
	{
		PrintCertHeader(bio_out, "TS Query", FORMAT);
		TS_REQ_print_bio(bio_out, ts_req);
		TS_REQ_free(ts_req);
		return true;
	}

	// TS_RESP
	BIO_seek(bio_in, pos);
	auto ts_resp = d2i_TS_RESP_bio(bio_in, NULL);
	if (ts_resp)
	{
		PrintCertHeader(bio_out, "TS Reply", FORMAT);
		TS_RESP_print_bio(bio_out, ts_resp);
		auto token = TS_RESP_get_token(ts_resp);
		if (token)
		{
			BIO_printf(bio_out, "\n\nToken:\n");
			PKCS7_print_ctx(bio_out, token, 2, NULL);
		}
		TS_RESP_free(ts_resp);
		return true;
	}

	// OCSP_REQUEST
	BIO_seek(bio_in, pos);
	auto ocsp_req = d2i_OCSP_REQUEST_bio(bio_in, NULL);
	if (ocsp_req)
	{
		PrintCertHeader(bio_out, "OCSP Request", FORMAT);
		OCSP_REQUEST_print(bio_out, ocsp_req, 0);
		OCSP_REQUEST_free(ocsp_req);
		return true;
	}

	// OCSP_RESPONSE
	BIO_seek(bio_in, pos);
	auto ocsp_resp = d2i_OCSP_RESPONSE_bio(bio_in, NULL);
	if (ocsp_resp)
	{
		PrintCertHeader(bio_out, "OCSP Response", FORMAT);
		OCSP_RESPONSE_print(bio_out, ocsp_resp, 0);
		OCSP_RESPONSE_free(ocsp_resp);
		return true;
	}

	return false;
}

bool ParseCertificateFile(BIO *bio_in, BIO *bio_out, PasswordCallback &callback)
{
	// try out to parse PEM format at first,
	// then the binary one
	if (ParseCertificateFileAsPEM(bio_in, bio_out, callback) ||
		ParseCertificateFileAsDER(bio_in, bio_out, callback))
	{
		return true;
	}

	return false;
}

bool DumpCertificate(const char *certFile, FILE *out, PasswordCallback callback)
{
	bool ret = false;
	BIO *bio_in = NULL;
	BIO *bio_out = NULL;

	// NOTE: open certificate as a binary file, some systems
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
	ret = ParseCertificateFile(bio_in, bio_out, callback);

cleanup:
	if (bio_out)
		BIO_free(bio_out);
	if (bio_in)
		BIO_free(bio_in);

	return ret;
}
