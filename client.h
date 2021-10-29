#include <getopt.h>
#include <cstdio>
#include <iostream>
#include <set>
#include <cstring>
#include <string>
#include <fstream> // files

#include <pcap.h>

// https://support.sas.com/documentation/onlinedoc/sasc/doc/lr2/lrv2ch15.htm
#include <sys/types.h>
#include <sys/uio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in_systm.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <net/if.h>

#include <unistd.h>

#include "base64.cpp"

struct s_args {
    std::string addr = "127.0.0.1";
    std::string port = "32323";
} args;

std::set<std::string> req_list {"register", "login", "list", "send", "fetch", "logout"};

void parseargs(int argc, char** argv);

void p_help();

std::string get_message(int argc, char** argv, std::string command);

std::string terminal_response(std::string server_response, std::string command);

int set_token(std::string token);

std::string get_token();
