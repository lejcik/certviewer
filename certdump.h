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

#include <stdio.h>
#include <functional>

// functor prototype for password callback handler,
// params:
// - char *buffer - callback stores the password into the buffer
// - int size     - length of the buffer
// return: password length in bytes, or -1 on error
using PasswordCallback = std::function<int(char*, int)>;

// dumps the provided certificate file into output FILE, calls password callback only
// when the file is password protected, returns TRUE on success
bool DumpCertificate(const char *certFile, FILE *out, PasswordCallback callback);
