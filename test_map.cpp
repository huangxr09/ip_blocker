#include <iostream>
#include "ip_blocker_map.h"

using namespace std;

int main(int argc, char* argv[]) {
  if(argc < 2) {
    cout << "usage: pro ip!" << endl;
    exit(1);
  }
  vector<string> ip_ranges{
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

  IpBlocker ib(ip_ranges);
  if(ib.IsIpInRanges(argv[1])) {
    cout << "true: " << argv[1] << endl;
  } else {
    cout << "false: " << argv[1] << endl;
  }
  return 0;
}
