#include "net.h"

#include <netinet/ip.h>
#include <sys/socket.h>
#include "my_buf.h"

net_device* net_dev_list;
