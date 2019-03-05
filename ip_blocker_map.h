#ifndef _UTILS_IPBLOCKER_
#define _UTILS_IPBLOCKER_
#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include <arpa/inet.h>
#include <stdint.h>

using namespace std;

class IpBlocker {
 public:
  IpBlocker(vector<string>& ip_ranges_raw);

  bool IsIpInRanges(const string &ip);
 private:
  map<unsigned int, map<unsigned int, int> > ip_check_map;
  unsigned int getMask(int prefix);
};

#endif

