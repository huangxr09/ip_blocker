#include "ip_blocker_bsearch.h"
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <stdint.h>
#include <algorithm>
using namespace std;

static vector<string> ip_ranges_raw{
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
 * 自定义的原始数据比较方案
 *****************************************************/
bool comp(string s1, string s2) {
  int mask1 = 0, mask2 = 0;
  auto pos = s1.find("/");

  if (pos != string::npos) {
    mask1 = atoi(s1.substr(pos + 1).c_str());
    s1 =  s1.substr(0, pos);
  } else {
    mask1 = 32;
  }

  pos = s2.find("/");

  if (pos != string::npos) {
    mask2 = atoi(s2.substr(pos + 1).c_str());
    s2 =  s2.substr(0, pos);
  } else {
    mask2 = 32;
  }

  unsigned long ip1 = htonl(inet_addr(s1.c_str()));
  unsigned long ip2 = htonl(inet_addr(s2.c_str()));
  return (ip1 < ip2 || (ip1 == ip2 && mask1 < mask2));
}

/*****************************************************
 * 转换mask
 *****************************************************/
in_addr_t netmask(int prefix) {
  if (prefix == 0) {
    return (~((in_addr_t) - 1));
  } else {
    return (~((1 << (32 - prefix)) - 1));
  }
}

/*****************************************************
 * 将ip转为整型
 *****************************************************/
unsigned long ipToUInt(const std::string ip) {
  int a, b, c, d;
  uint32_t addr = 0;

  if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
    return 0;
  }

  addr = a << 24;
  addr |= b << 16;
  addr |= c << 8;
  addr |= d;
  return addr;
}

/*****************************************************
 * 将1.1.1.1/24形式转换为整型范围
 *****************************************************/
vector<unsigned long> getIpRangesInt(vector<string> ips) {
  vector<unsigned long> ip_ranges;

  for (auto item : ips) {
    auto pos = item.find("/");
    string ipbase;
    int maskint = 0;

    if (pos != string::npos) {
      ipbase = item.substr(0, pos);
      maskint = atoi(item.substr(pos + 1).c_str());
    } else {
      ipbase = item;
      maskint = 32;
    }

    ip_ranges.push_back(ipToUInt(ipbase));
    ip_ranges.push_back(ipToUInt(ipbase) | ~netmask(maskint));
  }

  return ip_ranges;
}

/*****************************************************
 * 将区间融合,形成保序并且无交叉的区间序列
 *****************************************************/
vector<unsigned long> mergeRanges(vector<unsigned long> ips) {
  vector<unsigned long> res;
  int num = ips.size() / 2;
  unsigned long low = ips[0];
  unsigned long current = ips[1];

  for (int i = 0; i < num; i++) {
    if (current >= ips[2 * i]) {
      current = current > ips[2 * i + 1] ? current : ips[2 * i + 1];
    } else {
      res.push_back(low);
      res.push_back(current);
      low = ips[2 * i];
      current = ips[2 * i + 1];
    }
  }

  if (low >= res.back()) {
    res.push_back(low);
    res.push_back(current);
  } else {
    if (current >= res.back()) {
      res.back() = current;
    }
  }

  return res;
}

/*****************************************************
 * IpBlocker
 *****************************************************/
IpBlocker::IpBlocker() {
  sort(ip_ranges_raw.begin(), ip_ranges_raw.end(), comp);
  vector<unsigned long> tmp = getIpRangesInt(ip_ranges_raw);
  ip_ranges_res = mergeRanges(tmp);
}

/*****************************************************
 * IsIpInBlackList: 判断是否在黑名单内
 *****************************************************/
bool IpBlocker::IsIpInBlackList(const string &ip) {
  unsigned long ip_int = ipToUInt(ip);

  if (ip_int < ip_ranges_res[0] || ip_int > ip_ranges_res.back()) {
    return false;
  }

  unsigned int left = 0, right = ip_ranges_res.size();
  unsigned int mid = (left + right) / 2;

  while (left < right - 1) {
    if (ip_int < ip_ranges_res[mid]) {
      right = mid;
      mid = (left + right) / 2;
    } else if (ip_int > ip_ranges_res[mid]) {
      left = mid;
      mid = (left + right) / 2;
    } else {
      return true;
    }
  }

  return left % 2 == 0;
}
