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

#include <ostream>
#include <cstdio>
#include <stdio.h>
#include <time.h>

#include <filesystem>
namespace fs = std::filesystem;

#include <gtest/gtest.h>
using namespace ::testing;

#ifndef BOOL
	#define BOOL		int
	#define TRUE		1
	#define FALSE		0
#endif // BOOL

#include "utils.h"
