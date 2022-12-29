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

#pragma once

class CertParser final
{
public:
	CertParser();
	~CertParser();

	FILE *GetFilePtr()
	{
		return m_file;
	}

	void ParseFile();
	bool IsParsed() const
	{
		return m_parsed;
	}

	const std::vector<std::string> &GetContent() const
	{
		return m_content;
	}

private:
	std::string make_tmpname();
	FILE *make_tmpfile();
	void CloseFile();

private:
	// temporary file name
	std::string m_tmpname;
	// temporary file handle
	FILE *m_file{nullptr};
	// file can be parsed only once
	bool m_parsed{false};
	// parsed file content
	std::vector<std::string> m_content;
};

//////////////////////////////////////////////////////////////////////////

class TestFixureBase :
	public ::testing::Test
{
protected:
	/// test certs root path
	const fs::path CERT_ROOT = "certificates";

	void SetUp() override;
	void TearDown() override;

	// overrider for fs::path argument
	BOOL DumpCertificate(fs::path in, CertParser &out, const std::string &password = {});

	std::string GetObjectType() const;
	std::string GetFormat() const;
	bool FindDecodeFailedMsg() const;

	// plain search
	bool SearchContent(const std::string &pattern) const;
	// regular expression search
	bool SearchContentRE(const std::string& pattern) const;

protected:
	std::unique_ptr<CertParser> m_parser;
};
