#include <ifaddrs.h>
#include <sys/types.h>
#include <bits/ensure.h>

int getifaddrs(struct ifaddrs **ifap) {
    __ensure(0 && "getifaddrs is not implemented");
}

void freeifaddrs(struct ifaddrs *ifa) {
    __ensure(0 && "freeifaddrs is not implemented");
}