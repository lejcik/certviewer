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
#include "viewer.h"

#include "certdump.h"

void WINAPI HTMLHelpCallback(HWND hWindow, UINT helpID)
{
	SalamanderGeneral->OpenHtmlHelp(hWindow, HHCDisplayContext, helpID, FALSE);
}

BOOL InitViewer()
{
	if (!InitializeWinLib(PluginNameEN, DLLInstance))
		return FALSE;
	SetWinLibStrings(LoadStr(IDS_INVALID_NUM), LoadStr(IDS_PLUGINNAME));
	SetupWinLibHelp(HTMLHelpCallback);
	return TRUE;
}

void ReleaseViewer()
{
	ReleaseWinLib(DLLInstance);
}

//
// ****************************************************************************
// CPluginInterfaceForViewer
//

BOOL WINAPI
CPluginInterfaceForViewer::ViewFile(const char *name, int left, int top, int width, int height,
									UINT showCmd, BOOL alwaysOnTop, BOOL returnLock, HANDLE *lock,
									BOOL *lockOwner, CSalamanderPluginViewerData *viewerData,
									int enumFilesSourceUID, int enumFilesCurrentIndex)
{
	char szTmpFile[MAX_PATH];

	if (SalamanderGeneral->SalGetTempFileName(NULL, "CVW", szTmpFile, TRUE, NULL))
	{
		// create a temporary file which will be used for certificate info storage
		auto hTmpFile = fopen(szTmpFile, "w");
		if (!hTmpFile)
			return FALSE;

		// ask for the password once only per file view
		bool show_dlg = true;
		// password handler callback
		auto pwdHandler = [&show_dlg](char *buf, int size) -> int
		{
			*buf = 0;

			if (!show_dlg)
				return -1;
			show_dlg = false;

			CPasswordDialog dlg(SalamanderGeneral->GetMsgBoxParent(), buf, size);
			return (dlg.Execute() == IDOK) ? static_cast<int>(strlen(buf)) : -1;
		};

		// try out to dump info of the certificate
		if (!DumpCertificate(name, hTmpFile, pwdHandler))
		{
			fclose(hTmpFile);

			// fallback, show raw content if decoding of the certificate file has failed
			CSalamanderPluginInternalViewerData data{};
			data.Size = sizeof(data);
			data.FileName = name;
			data.Mode = 0;
			data.Caption = NULL;
			data.WholeCaption = FALSE;
			int err = 0;
			return SalamanderGeneral->ViewFileInPluginViewer(NULL, &data, FALSE, NULL, "cert_dump.txt", err);
		}

		fclose(hTmpFile);

		// compose viewer window title
		char szTitle[2000];
		sprintf_s(szTitle, "%s - %s", name, LoadStr(IDS_PLUGINNAME));

		// setup built-in viewer
		CSalamanderPluginInternalViewerData data;
		data.Size = sizeof(data);
		data.FileName = szTmpFile;
		data.Mode = 0;
		data.Caption = szTitle;
		data.WholeCaption = TRUE;

		int err = 0;
		if (SalamanderGeneral->ViewFileInPluginViewer(NULL, &data, TRUE, NULL, "cert_dump.txt", err))
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOL WINAPI
CPluginInterfaceForViewer::CanViewFile(const char *name)
{
	return TRUE;
}
