#include "ip_blocker_map.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <stdint.h>
using namespace std;

/*****************************************************
 * convert mask (0-32) to interger
 *****************************************************/
unsigned int IpBlocker::getMask(int prefix) {
  if (prefix == 0) {
    return (~((in_addr_t) - 1));
  } else {
    return (~((1 << (32 - prefix)) - 1));
  }
}

/*****************************************************
 * IpBlocker constructor
 *****************************************************/
IpBlocker::IpBlocker(vector<string>& ip_ranges_raw) {
  map<int, int> mask_parts;

  for (auto &item : ip_ranges_raw) {
    auto pos = item.find("/");

    if (pos != string::npos) {
      string ipbase = item.substr(0, pos);
      unsigned int mask = atoi(item.substr(pos + 1).c_str());
      ip_check_map[getMask(mask)][htonl(inet_addr(ipbase.c_str()))] = 1;
    } else {
      ip_check_map[getMask(32)][htonl(inet_addr(item.c_str()))] = 1;
    }
  }
}

/*****************************************************
 * IsIpInRanges: 
 *****************************************************/
bool IpBlocker::IsIpInRanges(const string &ip) {
  unsigned int ip_int = htonl(inet_addr(ip.c_str()));

  for (auto &item : ip_check_map) {
    if (ip_check_map[item.first].find(ip_int & item.first) != ip_check_map[item.first].end()) {
      return true;
    }
  }

  return false;
}
