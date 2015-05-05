#ifndef IPTC_H_
#define IPTC_H_

extern "C" {

bool dropIP(const char* ip, bool isIPv4 = true);
bool removeDropIP(const char* ip, bool isIPv4 = true);

}
#endif /* IPTC_H_ */
