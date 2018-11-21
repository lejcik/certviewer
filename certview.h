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

// globalni data
extern const char *PluginNameEN; // neprekladane jmeno pluginu, pouziti pred loadem jazykoveho modulu + pro debug veci
extern HINSTANCE DLLInstance;    // handle k SPL-ku - jazykove nezavisle resourcy
extern HINSTANCE HLanguage;      // handle k SLG-cku - jazykove zavisle resourcy

// obecne rozhrani Salamandera - platne od startu az do ukonceni pluginu
extern CSalamanderGeneralAbstract *SalamanderGeneral;

// rozhrani poskytujici upravene Windows controly pouzivane v Salamanderovi
extern CSalamanderGUIAbstract *SalamanderGUI;

BOOL InitViewer();
void ReleaseViewer();

// globalni data
extern BOOL CfgSavePosition;               // ukladat pozici okna/umistit dle hlavniho okna
extern WINDOWPLACEMENT CfgWindowPlacement; // neplatne, pokud CfgSavePosition != TRUE

extern DWORD LastCfgPage;   // start page (sheet) in configuration dialog

// [0, 0] - pro otevrena okna viewru: konfigurace pluginu se zmenila
#define WM_USER_VIEWERCFGCHNG WM_APP + 3346
// [0, 0] - pro otevrena okna viewru: je treba podriznou historie
#define WM_USER_CLEARHISTORY WM_APP + 3347
// [0, 0] - pro otevrena okna vieweru: Salamander pregeneroval fonty, mame zavolat SetFont() listam
#define WM_USER_SETTINGCHANGE WM_APP + 3248


char *LoadStr(int resID);


class CPluginInterface:
      public CPluginInterfaceAbstract
{
  public:
    virtual void WINAPI About(HWND parent);

    virtual BOOL WINAPI Release(HWND parent, BOOL force);

    virtual void WINAPI LoadConfiguration(HWND parent, HKEY regKey, CSalamanderRegistryAbstract *registry);
    virtual void WINAPI SaveConfiguration(HWND parent, HKEY regKey, CSalamanderRegistryAbstract *registry);
    virtual void WINAPI Configuration(HWND parent);

    virtual void WINAPI Connect(HWND parent, CSalamanderConnectAbstract *salamander);

    virtual void WINAPI ReleasePluginDataInterface(CPluginDataInterfaceAbstract *pluginData) {}

    virtual CPluginInterfaceForArchiverAbstract * WINAPI GetInterfaceForArchiver() {return NULL;}
    virtual CPluginInterfaceForViewerAbstract * WINAPI GetInterfaceForViewer();
    virtual CPluginInterfaceForMenuExtAbstract * WINAPI GetInterfaceForMenuExt() {return NULL;}
    virtual CPluginInterfaceForFSAbstract * WINAPI GetInterfaceForFS() {return NULL;}
    virtual CPluginInterfaceForThumbLoaderAbstract * WINAPI GetInterfaceForThumbLoader() {return NULL;}

    virtual void WINAPI Event(int event, DWORD param);
    virtual void WINAPI ClearHistory(HWND parent);
    virtual void WINAPI AcceptChangeOnPathNotification(const char *path, BOOL includingSubdirs) {}

    virtual BOOL WINAPI UninstallUnregisteredComponents(HWND parent, char *componentsDescr, BOOL *uninstallSPL,
                                                        BOOL *uninstallLangDir, const char *pluginDir,
                                                        CDynamicString *deleteFileList) {return FALSE;}

    virtual void WINAPI PasswordManagerEvent(HWND parent, int event) {}
};

// rozhrani pluginu poskytnute Salamanderovi
extern CPluginInterface PluginInterface;

// otevre konfiguracni dialog; pokud jiz existuje, zobrazi hlasku a vrati se
void OnConfiguration(HWND hParent);

// otevre About okno
void OnAbout(HWND hParent);
