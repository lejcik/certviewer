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
#include "../certdump.h"
#include <fstream>
#include <regex>

#ifdef _WIN32
// fix posix deprecated function names
#define unlink		_unlink
#endif

CertParser::CertParser() :
	m_tmpname{make_tmpname()},
	m_file{make_tmpfile()}
{
}

CertParser::~CertParser()
{
	CloseFile();
	// erase the temp file
	unlink(m_tmpname.c_str());
}

void CertParser::ParseFile()
{
	// parse the file once only
	if (m_parsed)
		return;
	m_parsed = true;

	// close the temp file and read it line by line
	CloseFile();
	std::ifstream infile(m_tmpname.c_str());
	std::string line;
	while (std::getline(infile, line))
	{
#ifdef _DEBUG
		//std::cout << line << std::endl;
#endif
		m_content.push_back(std::move(line));
	}
}

std::string CertParser::make_tmpname() const
{
	std::string buffer;
	buffer.resize(1024);

#ifdef _WIN32
	// windows with CRT security extensions
	auto err = tmpnam_s(buffer.data(), buffer.length());
	if (err)
		std::cerr << "! failed to get temp name, error: " << err << std::endl;
#else
	// other posix compatible OS
	return tmpnam(buffer);
#endif
	return buffer;
}

FILE *CertParser::make_tmpfile() const
{
	if (m_tmpname.empty())
		return nullptr;

#ifdef _WIN32
	// windows with CRT security extensions
	FILE *f = nullptr;
	auto err = fopen_s(&f, m_tmpname.c_str(), "w");
	if (err)
		std::cerr << "! failed to create temp file, error: " << err << std::endl;
	return f;
#else
	// other posix compatible OS
	return fopen(m_tmpname.c_str(), "w");
#endif
}

void CertParser::CloseFile()
{
	if (m_file)
		fclose(m_file);
	m_file = nullptr;
}

//////////////////////////////////////////////////////////////////////////

void TestFixureBase::SetUp()
{
	m_parser = std::make_unique<CertParser>();
	ASSERT_NE(m_parser->GetFilePtr(), nullptr);
}

void TestFixureBase::TearDown()
{
	m_parser.reset();
}

bool TestFixureBase::DumpCertificate(const fs::path &in, CertParser &out, const std::string &password)
{
	auto pwdHandler = [&password](char *buf, int size) -> int
		{
			if (password.empty())
				return -1;
#ifdef _WIN32
			strncpy_s(buf, size, password.c_str(), password.length());
#else
			strncpy(buf, password.c_str(), size);
#endif
			return static_cast<int>(password.size());
		};

	const auto ret = ::DumpCertificate(in.string().c_str(), out.GetFilePtr(), pwdHandler);
	out.ParseFile();
	return ret;
}

std::string TestFixureBase::GetObjectType() const
{
	const auto& content = m_parser->GetContent();
	if (content.size() < 1)
		return {};
	// object type is on the first line
	std::regex re("^Object type:\\s+(.+)");
	std::smatch matcher;
	std::regex_match(content[0], matcher, re);
	if (matcher.size() == 2)
		return matcher[1];
	return {};
}

std::string TestFixureBase::GetFormat() const
{
	const auto& content = m_parser->GetContent();
	if (content.size() < 2)
		return {};
	// format is on the second line
	std::regex re("^Format:\\s+(.+)");
	std::smatch matcher;
	std::regex_match(content[1], matcher, re);
	if (matcher.size() == 2)
		return matcher[1];
	return {};
}

bool TestFixureBase::FindDecodeFailedMsg() const
{
	return SearchContent("unsupported PEM object") ||
		   SearchContent("Failed to load") ||
		   SearchContent("Certificate file may be corrupted");
}

bool TestFixureBase::IsFilePasswordProtected() const
{
	return SearchContent("password protected");
}

bool TestFixureBase::SearchContent(const std::string &pattern) const
{
	return std::any_of(m_parser->GetContent().begin(), m_parser->GetContent().end(),
		[&pattern](const std::string& line)
		{
			return line.find(pattern) != std::string::npos;
		});
}

bool TestFixureBase::SearchContentRE(const std::string &pattern) const
{
	std::regex re(pattern);
	std::smatch matcher;

	return std::any_of(m_parser->GetContent().begin(), m_parser->GetContent().end(),
		[&re, &matcher](const std::string& line)
		{
			std::regex_match(line, matcher, re);
			return (matcher.size() >= 1); // at least 1 match
		});
}
