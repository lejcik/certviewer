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

TEST_F(DerCertificate, EC_Parameters)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ec-params.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "EC Parameters");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("ECDSA-Parameters:"));
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

TEST_F(DerCertificate, PKCS8_Certificate_EncryptedPrivateKey)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs8-private-key-encrypted.der", *m_parser, "password"));
	EXPECT_STREQ(GetObjectType().c_str(), "Encrypted Private Key");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(IsFilePasswordProtected());
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

TEST_F(DerCertificate, PKCS8_Certificate_EncryptedPrivateKey_WrongPassword)
{
	EXPECT_FALSE(DumpCertificate(CERT_PATH / "pkcs8-private-key-encrypted.der", *m_parser, "wrong-password"));
}

TEST_F(DerCertificate, PKCS8_Certificate_EncryptedPrivateKey_NoPassword)
{
	EXPECT_FALSE(DumpCertificate(CERT_PATH / "pkcs8-private-key-encrypted.der", *m_parser));
}

TEST_F(DerCertificate, PKCS8_Certificate_EncryptedPrivateKey_EmptyPassword)
{
	// don't ask user for password if certificate file uses zero length password!
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs8-private-key-encrypted-empty-pwd.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "Encrypted Private Key");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(IsFilePasswordProtected());
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

TEST_F(DerCertificate, PKCS12_Certificate)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs12-encrypted.p12", *m_parser, "password"));
	EXPECT_STREQ(GetObjectType().c_str(), "PKCS#12 Encrypted Certificate");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(IsFilePasswordProtected());
	EXPECT_TRUE(SearchContent("PKCS7 Encrypted data"));
	// both, public and private keys have to be present!
	EXPECT_TRUE(SearchContent("Certificate:"));
	EXPECT_TRUE(SearchContent("Private-Key:"));
}

TEST_F(DerCertificate, PKCS12_Certificate_WrongPassword)
{
	// returns true also on wrong password, it displays what's possible about the PKCS12 container
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs12-encrypted.p12", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "PKCS#12 Encrypted Certificate");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(IsFilePasswordProtected());
	EXPECT_TRUE(SearchContent("PKCS7 Encrypted data"));
	// private key should not be unpacked
	EXPECT_TRUE(SearchContent("Invalid password"));
}

TEST_F(DerCertificate, PKCS12_Certificate_EmptyPassword)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs12-encrypted-empty-pwd.p12", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "PKCS#12 Encrypted Certificate");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(IsFilePasswordProtected());
	EXPECT_TRUE(SearchContent("PKCS7 Encrypted data"));
	EXPECT_TRUE(SearchContent("Certificate:"));
}

TEST_F(DerCertificate, PKCS12_Certificate_UnsupportedAlgorithm)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "pkcs12-encrypted-unsupported-algorithm.p12", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "PKCS#12 Encrypted Certificate");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(IsFilePasswordProtected());
	EXPECT_TRUE(SearchContent("PKCS7 Encrypted data"));
	// some algorithms are not present on certain platforms
	EXPECT_TRUE(SearchContent("Unsupported algorithm"));
}

TEST_F(DerCertificate, DH_Parameters)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "dh-params.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "DH Parameters");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("DH Parameters:"));
}

TEST_F(DerCertificate, SSL_SessionParameters)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ssl-session-params.der", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "SSL Session Parameters");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("SSL-Session:"));
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

TEST_F(DerCertificate, TS_Query)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ts-query.tsq", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "TS Query");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Hash Algorithm:"));
}

TEST_F(DerCertificate, TS_Reply)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ts-reply.tsr", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "TS Reply");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("Status info:"));
}

TEST_F(DerCertificate, OCSP_Request)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ocsp-request.req", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "OCSP Request");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("OCSP Request Data:"));
}

TEST_F(DerCertificate, OCSP_Response)
{
	EXPECT_TRUE(DumpCertificate(CERT_PATH / "ocsp-response.res", *m_parser));
	EXPECT_STREQ(GetObjectType().c_str(), "OCSP Response");
	EXPECT_STREQ(GetFormat().c_str(), FORMAT_TYPE);
	EXPECT_FALSE(FindDecodeFailedMsg());
	EXPECT_TRUE(SearchContent("OCSP Response Data:"));
}
