/**
 * @file client.h
 * @author Tereza Burianova, xburia28
 * @date 02 Nov 2021
 * @brief ISA project - client implementation, header.
 * 
 **/

#include <getopt.h>
#include <cstdio>
#include <iostream>
#include <set>
#include <cstring>
#include <string>
#include <fstream> // files
#include <regex>
#include <unistd.h>
#include "base64.h"

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


struct s_args {
    std::string addr = "127.0.0.1";
    std::string port = "32323";
} args;

/**
 * Parse command line arguments.
 * @param argc Number of arguments.
 * @param argv Array of arguments.
 */
void parseargs(int argc, char** argv);

 /**
  * Print help.
  */
void p_help();

/**
 * Send data to the server.
 * @param message Input message.
 * @param sockfd Network socket.
 * @return 1 if an error occurs, else 0.
 */
int send_data(std::string message, int sockfd);

/**
 * Receive data from the server.
 * @param sockfd Network socket.
 * @return Empty string if an error occurs, else the server output message.
 */
std::string receive_data(int sockfd);

/**
 * Build the request that is sent to the server according to the program arguments.
 * @param argc Number of arguments.
 * @param argv Array of arguments.
 * @param command The current command.
 * @return Server input message.
 */
std::string get_message(int argc, char** argv, std::string command);

/**
 * Perform actions according to the server response and build the printed response.
 * @param server_response The response sent by server.
 * @param command The current command.
 * @return Parsed server response.
 */
std::string terminal_response(std::string server_response, std::string command);

/**
 * Parse the server response to individual parts of the message.
 * @param server_response The response sent by server.
 * @param list_fetch True if current command is "fetch" or "list".
 * @return Array of strings (parsed parts of the message).
 */
std::vector<std::string> split_response(std::string server_response, bool list_fetch);

/**
 * Replace all occurrences of a substring.
 * @param msg String.
 * @param replaced Substring that is being replaced.
 * @param replace String replacing the substring.
 * @return Edited string.
 */
std::string replace_all(std::string msg, std::string replaced, std::string replace);

/**
 * Change escaped characters to special form. For later message parsing purposes.
 * @param input_msg String.
 * @return Edited string.
 */
std::string escaped_to_special(std::string input_msg);

/**
 * Change special form back to unescaped characters.
 * @param input_msg String.
 * @return Edited string.
 */
std::string special_to_char(std::string input_msg);

/**
 * Escape special characters.
 * @param input_msg String.
 * @return Edited string.
 */
std::string char_to_escaped(std::string input_msg);

/**
 * Perform various token actions.
 * @param state True if server response was success.
 * @param command Current command.
 * @param token Token string.
 * @return 1 if an error occurs, else 0.
 */
int resolve_tokens(bool state, std::string command, std::string token);

/**
 * Write token into the file.
 * @param token Token string.
 * @return 1 if an error occurs, else 0.
 */
int set_token(std::string token);

/**
 * Read token from file.
 * @return Token string.
 */
std::string get_token();
