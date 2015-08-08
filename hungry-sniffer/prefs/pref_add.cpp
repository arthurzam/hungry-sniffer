#include "Protocol.h"
#include "general_modules.h"
#include "general_ui.h"

void addPrefs(HungrySniffer_Core& core)
{
    HungrySniffer_Core::Preference& pref = core.addProtocolPreference({"General"});
    pref.add({"Modules", GeneralModules::init});
    pref.add({"UI", GeneralUI::init});
}
