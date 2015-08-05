#include "Protocol.h"
#include "general_ui.h"

void addPrefs(HungrySniffer_Core& core)
{
    HungrySniffer_Core::Preference& pref = core.addProtocolPreference({"General"});
    pref.add({"UI", GeneralUI::init});
}
