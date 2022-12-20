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
#include <openssl/pem.h>

class DerCertificate :
	public TestFixureBase
{
protected:
	const fs::path CERT_PATH = CERT_ROOT / "der";
	static constexpr const char FORMAT_TYPE[] = "DER";
};

TEST_F(DerCertificate, X509_Certificate)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "x509-cert.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "X509 Certificate");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContentRE("^Certificate:"));
}

TEST_F(DerCertificate, RSA_Certificate_PrivateKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "rsa-private-key.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "RSA Private Key");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

TEST_F(DerCertificate, RSA_Certificate_PublicKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "rsa-public-key.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "RSA Public Key");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Public-Key:"));
}

TEST_F(DerCertificate, DSA_Certificate_PrivateKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "dsa-private-key.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "DSA Private Key");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

TEST_F(DerCertificate, DSA_Certificate_PublicKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "dsa-public-key.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "DSA Public Key");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Public-Key:"));
}

TEST_F(DerCertificate, EC_PrivateKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ec-private-key.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "EC Private Key");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

TEST_F(DerCertificate, EC_PublicKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ec-public-key.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "EC Public Key");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Public-Key:"));
}

TEST_F(DerCertificate, PKCS7_Certificate)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs7-cert.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "PKCS7");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	// there has to be at least 1 certificate
	EXPECT_TRUE(SearchContent("cert_info:"));
}

TEST_F(DerCertificate, PKCS7_Certificate_CRL)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs7-cert-crl.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "PKCS7");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	// there has to be at least 1 CRL
	EXPECT_TRUE(SearchContent("crl:"));
}

TEST_F(DerCertificate, CMS)
{
	// NOTE: CMS file has the same form as PKCS7, that's why it is identified as PKCS7
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "cms.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "PKCS7");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("PKCS7:"));
}
