#ifndef CURO_LOG_H
#define CURO_LOG_H

#include "config.h"

#if DEBUG_ETHERNET > 0
#define LOG_ETHERNET(...) printf("[ETHER] ");printf(__VA_ARGS__)
#else
#define LOG_ETHERNET(...)
#endif

#if DEBUG_IP > 0
#define LOG_IP(...) printf("[IP] ");printf(__VA_ARGS__);
#else
#define LOG_IP(...)
#endif

#if DEBUG_ARP > 0
#define LOG_ARP(...) printf("[ARP] ");printf(__VA_ARGS__);
#else
#define LOG_ARP(...)
#endif

#if DEBUG_ICMP > 0
#define LOG_ICMP(...) printf("[ICMP] ");printf(__VA_ARGS__);
#else
#define LOG_ICMP(...)
#endif

#if DEBUG_NAT > 0
#define LOG_NAT(...) printf("[NAT] ");printf(__VA_ARGS__);
#else
#define LOG_NAT(...)
#endif

#if DEBUG_IPV6 > 0
#define LOG_IPV6(...) printf("[IPv6] ");printf(__VA_ARGS__);
#else
#define LOG_IPV6(...)
#endif


#define LOG_ERROR(...) fprintf(stderr, "[ERROR %s:%d] ", __FILE__, __LINE__);fprintf(stderr, __VA_ARGS__);

#endif //CURO_LOG_H
