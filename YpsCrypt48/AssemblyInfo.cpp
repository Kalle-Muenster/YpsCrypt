#include "settings.h"

using namespace System;
using namespace System::Reflection;
using namespace System::Runtime::CompilerServices;
using namespace System::Runtime::InteropServices;
using namespace System::Security::Permissions;

//
// Allgemeine Informationen �ber eine Assembly werden �ber die folgenden
// Attribute gesteuert. �ndern Sie diese Attributwerte, um die Informationen zu �ndern,
// die einer Assembly zugeordnet sind.
//
[assembly:AssemblyTitleAttribute(L"YpsCrypt")];
[assembly:AssemblyDescriptionAttribute(L"CrypticYpsing")];
[assembly:AssemblyConfigurationAttribute(L"")];
[assembly:AssemblyCompanyAttribute(L"")];
[assembly:AssemblyProductAttribute(L"YpsCrypt")];
[assembly:AssemblyCopyrightAttribute(L"Copyright (c)  schon vor Urzeit-kreb zeiten lange her")];
[assembly:AssemblyTrademarkAttribute(L"Yps")];
[assembly:AssemblyCultureAttribute(L"")];

//
// Versionsinformationen f�r eine Assembly bestehen aus den folgenden vier Werten:
//
//      Hauptversion
//      Nebenversion
//      Buildnummer
//      Revision
//
// Sie k�nnen alle Werte angeben oder f�r die Revisions- und Buildnummer den Standard
// �bernehmen, indem Sie "*" eingeben:

[assembly:AssemblyVersionAttribute(YpsCryptVersionString)];

[assembly:ComVisible(false)];

[assembly:CLSCompliantAttribute(true)];
