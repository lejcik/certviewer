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

//
// CPluginInterfaceForViewer
//

class CPluginInterfaceForViewer:
      public CPluginInterfaceForViewerAbstract
{
public:
    BOOL WINAPI ViewFile(const char *name, int left, int top, int width, int height,
                         UINT showCmd, BOOL alwaysOnTop, BOOL returnLock, HANDLE *lock,
                         BOOL *lockOwner, CSalamanderPluginViewerData *viewerData,
                         int enumFilesSourceUID, int enumFilesCurrentIndex) override;
    BOOL WINAPI CanViewFile(const char *name) override;
};
