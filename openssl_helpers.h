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

// this file contains private (static) functions and slightly modified code chunks
// that were taken from openssl project

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/cms.h>

void PrintSeparator(BIO *bio_out);

int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb);

void PKCS7_print_certs(BIO *bio_out, const PKCS7 *pkcs7);
