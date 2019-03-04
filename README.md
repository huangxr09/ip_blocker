# ip_blocker
c++ codes for blocking ips in specified ranges (eg: 123.123.123.0/24)

2 implements:
1. Base on map search.  O(k*log(m))  while k*m = n
2. Base on self-implemented binary search.  O(log(n))

Both of them require pre-process to build cached data for quick search.
