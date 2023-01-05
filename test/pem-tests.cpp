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

#include "utils.h"
#include <openssl/pem.h>

class PemCertificate :
	public TestFixureBase
{
protected:
	const fs::path CERT_PATH = CERT_ROOT / "pem";
	static constexpr const char FORMAT_TYPE[] = "PEM";
};

// run test for each cert type, as they are listed in openssl/pem.h,
// see the PEM_STRING_* constants

TEST_F(PemCertificate, X509_Certificate_Old)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "x509-cert.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_X509_OLD);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContentRE("^Certificate:"));
}

TEST_F(PemCertificate, X509_Certificate)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "cert.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_X509);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContentRE("^Certificate:"));
}

TEST_F(PemCertificate, X509_Trusted_Certificate)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "cert-trusted.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_X509_TRUSTED);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContentRE("^Certificate:"));
}

TEST_F(PemCertificate, X509_Certificate_RequestOld)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "cert-new-request.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_X509_REQ_OLD);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContentRE("^Certificate Request:"));
}

TEST_F(PemCertificate, X509_Certificate_Request)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "cert-request.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_X509_REQ);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContentRE("^Certificate Request:"));
}

TEST_F(PemCertificate, X509_Certificate_CRL)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "x509-crl.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_X509_CRL);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContentRE("^Certificate Revocation List \\(CRL\\):"));
}

// test disabled as I don't have a sample file
TEST_F(PemCertificate, DISABLED_Certificate_AnyPrivateKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "any-private-key.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_EVP_PKEY);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
}

TEST_F(PemCertificate, Certificate_PublicKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "cert-public-key.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_PUBLIC);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Public-Key:"));
}

TEST_F(PemCertificate, RSA_Certificate_PrivateKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "rsa-private-key.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_RSA);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

TEST_F(PemCertificate, RSA_Certificate_PublicKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "rsa-public-key.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_RSA_PUBLIC);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Public-Key:"));
}

TEST_F(PemCertificate, DSA_Certificate_PrivateKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "dsa-private-key.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_DSA);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

TEST_F(PemCertificate, DSA_Certificate_PublicKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "dsa-public-key.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_DSA_PUBLIC);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Public-Key:"));
}

TEST_F(PemCertificate, PKCS7_Certificate)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs7-cert.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_PKCS7);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("PKCS7:"));
	// there has to be at least 1 certificate
	EXPECT_TRUE(SearchContent("cert_info:"));
}

TEST_F(PemCertificate, PKCS7_Certificate_CRL)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs7-cert-crl.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "PKCS7");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("PKCS7:"));
	// there has to be at least 1 CRL
	EXPECT_TRUE(SearchContent("crl:"));
}

TEST_F(PemCertificate, PKCS7_Certificate_SignedData)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs7-cert-signed-data.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_PKCS7_SIGNED);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("PKCS7:"));
	EXPECT_TRUE(SearchContent("pkcs7-signedData"));
}

TEST_F(PemCertificate, PKCS8_Certificate_EncryptedPrivateKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs8-private-key-encrypted.pem", *m_parser, "password"));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_PKCS8);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("password protected"));
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

TEST_F(PemCertificate, PKCS8_Certificate_EncryptedPrivateKey_WrongPassword)
{
	EXPECT_FALSE(DumpCertificate(CERT_PATH / "pkcs8-private-key-encrypted.pem", *m_parser, "wrong-password"));
}

TEST_F(PemCertificate, PKCS8_Certificate_EncryptedPrivateKey_NoPassword)
{
	EXPECT_FALSE(DumpCertificate(CERT_PATH / "pkcs8-private-key-encrypted.pem", *m_parser));
}

TEST_F(PemCertificate, PKCS8_Certificate_EncryptedPrivateKey_EmptyPassword)
{
	// don't ask user for password if certificate file uses zero length password!
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs8-private-key-encrypted-empty-pwd.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_PKCS8);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("password protected"));
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

TEST_F(PemCertificate, DH_Parameters)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "dh-params.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_DHPARAMS);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("DH Parameters:"));
}

TEST_F(PemCertificate, DHX_Parameters)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "dhx-params.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_DHXPARAMS);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("DH Parameters:"));
}

TEST_F(PemCertificate, SSL_SessionParameters)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ssl-session-params.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_SSL_SESSION);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("SSL-Session:"));
}

TEST_F(PemCertificate, DSA_Parameters)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "dsa-params.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_DSAPARAMS);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("DSA-Parameters:"));
}

// this object seems not to be supported by openssl
TEST_F(PemCertificate, DISABLED_ECDSA_PublicKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ecdsa-public-key.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_ECDSA_PUBLIC);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
}

TEST_F(PemCertificate, EC_Parameters)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ec-params.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_ECPARAMETERS);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("EC-Parameters:"));
}

TEST_F(PemCertificate, EC_PrivateKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ec-private-key.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_ECPRIVATEKEY);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

// this object seems not to be supported by openssl
TEST_F(PemCertificate, DISABLED_Parameters)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "cert-params.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_PARAMETERS);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
}

TEST_F(PemCertificate, CMS)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "cms.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_CMS);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("CMS_ContentInfo:"));
}

TEST_F(PemCertificate, PasswordProtectedKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pwd-protected-key.pem", *m_parser, "password"));
	EXPECT_STREQ(GetObjectType().c_str(), PEM_STRING_RSA);
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("password protected"));
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

TEST_F(PemCertificate, PasswordProtectedKey_WrongPassword)
{
	EXPECT_FALSE(DumpCertificate(CERT_PATH / "pwd-protected-key.pem", *m_parser, "wrong-password"));
}

TEST_F(PemCertificate, PasswordProtectedKey_NoPassword)
{
	EXPECT_FALSE(DumpCertificate(CERT_PATH / "pwd-protected-key.pem", *m_parser));
}

TEST_F(PemCertificate, CorruptedCertificate)
{
	EXPECT_FALSE(DumpCertificate(CERT_PATH / "corrupted.pem", *m_parser));
}

TEST_F(PemCertificate, UnknownObjectName)
{
	EXPECT_FALSE(DumpCertificate(CERT_PATH / "unknown-obj.pem", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "TEST OBJECT");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_TRUE(FindDecodeFailedMsg());
}

TEST_F(PemCertificate, CertificateBundle)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "bundle.pem", *m_parser));
	EXPECT_FALSE(FindDecodeFailedMsg());

	// bundle certificates order
	static const char *bundle_certs[] = { PEM_STRING_DSA, PEM_STRING_X509_REQ, PEM_STRING_X509, 0 };

	// verify the certs order
	auto expected = bundle_certs;
	for (auto line : m_parser->GetContent())
	{
		if (line.find("Object type:") == std::string::npos)
			continue;
		EXPECT_TRUE(line.find(*expected) != std::string::npos);
		expected++;
		if (*expected == 0)
			break;
	}
}
