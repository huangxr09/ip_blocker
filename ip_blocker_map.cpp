#include "ip_blocker.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <stdint.h>
using namespace std;

static vector<string> ip_ranges{
  "2.144.0.0/14",
  "2.176.0.0/12",
  "5.0.0.0/16",
  "5.22.0.0/17",
  "5.22.192.0/19",
  "212.110.156.0/22",
  "213.59.160.0/20",
  "217.147.8.0/22",
  "217.175.0.0/20"
};

/*****************************************************
 * 转换mask
 *****************************************************/
unsigned int IpBlocker::GetMask(int prefix) {
  if (prefix == 0) {
    return (~((in_addr_t) - 1));
  } else {
    return (~((1 << (32 - prefix)) - 1));
  }
}

/*****************************************************
 * IpBlocker
 *****************************************************/
IpBlocker::IpBlocker() {
  map<int, int> mask_parts;

  // 分解IP段配置保存
  for (auto &item : ip_ranges) {
    auto pos = item.find("/");

    if (pos != string::npos) {
      string ipbase = item.substr(0, pos);
      unsigned int mask = atoi(item.substr(pos + 1).c_str());
      ip_check_map[GetMask(mask)][htonl(inet_addr(ipbase.c_str()))] = 1;
    } else {
      ip_check_map[GetMask(32)][htonl(inet_addr(item.c_str()))] = 1;
    }
  }
}

/*****************************************************
 * IsIpInBlackList: 判断是否在黑名单内
 *****************************************************/
bool IpBlocker::IsIpInBlackList(const string &ip) {
  unsigned int ip_int = htonl(inet_addr(ip.c_str()));

  for (auto &item : ip_check_map) {
    if (ip_check_map[item.first].find(ip_int & item.first) != ip_check_map[item.first].end()) {
      return true;
    }
  }

  return false;
}
